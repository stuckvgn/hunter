#!/usr/bin/env python3
"""tracker — persistent per-program state for bug-bounty work.

State lives at ./state/<handle>.json, one file per tracked program. Every
phase of hunt.py writes into that file so I can pick up any target at any
time and know what's been done, what the policy said, what I found, and
what to do next.

Usage:
  tracker.py add <handle> [--platform P]    # start tracking a program
  tracker.py list [--status S]              # all programs (optionally filtered)
  tracker.py show <handle>                  # single program detail
  tracker.py advance <handle> <phase> [--output PATH]
  tracker.py note <handle> "free text"
  tracker.py policy <handle> --allowed yes|no|unknown --notes "..."
  tracker.py finding <handle> add --severity H --title "..." --url "..." [--template T]
  tracker.py finding <handle> list
  tracker.py next                           # suggest next action across all programs

Status is derived from phases — you never set it directly.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
STATE_DIR = HERE / "state"
CATALOG_PATH = STATE_DIR / "_catalog.json"
TRIAGE_PATH = STATE_DIR / "_triage.json"
BOUNTIES_CLI = HERE / "bounties.py"

sys.path.insert(0, str(HERE))  # allow importing bounties / triage as modules

# Phase ordering — advance() fills them in sequence.
PHASES = ["scope", "policy", "enum", "archive", "live", "crawl", "js_mine", "param_mine", "scan", "reported"]
PASSIVE_PHASES = {"scope", "policy", "enum", "archive"}
ACTIVE_PHASES = {"live", "crawl", "js_mine", "param_mine", "scan"}


# ---------- io ----------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def state_path(handle: str) -> Path:
    return STATE_DIR / f"{handle}.json"


def load(handle: str) -> dict | None:
    p = state_path(handle)
    return json.loads(p.read_text()) if p.exists() else None


def save(state: dict) -> None:
    STATE_DIR.mkdir(exist_ok=True)
    state["updated_at"] = _now()
    state_path(state["handle"]).write_text(json.dumps(state, indent=2, default=str) + "\n")


def all_states() -> list[dict]:
    if not STATE_DIR.exists():
        return []
    # Files starting with `_` are shared artifacts (_catalog, _triage),
    # not per-program state. Skip them.
    return [
        json.loads(p.read_text())
        for p in sorted(STATE_DIR.glob("*.json"))
        if not p.name.startswith("_")
    ]


# ---------- derived status ----------

def current_status(state: dict) -> str:
    """Return the furthest phase completed, else the blocker."""
    phases = state["phases"]
    if state.get("automation_allowed") is False:
        return "passive_only"
    done = [p for p in PHASES if phases.get(p)]
    if not done:
        return "new"
    if "reported" in done:
        return "reported"
    return f"after:{done[-1]}"


# ---------- init ----------

def fetch_program(handle: str, platform: str | None) -> dict:
    cmd = [str(BOUNTIES_CLI), "show", handle, "--json"]
    if platform:
        cmd += ["--platform", platform]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        sys.exit(f"bounties CLI failed: {r.stderr.strip() or r.stdout.strip()}")
    return json.loads(r.stdout)


def new_state(prog: dict) -> dict:
    return {
        "handle": prog["handle"],
        "platform": prog["platform"],
        "name": prog["name"],
        "program_url": prog["url"],
        "max_bounty": prog.get("max_bounty"),
        "min_bounty": prog.get("min_bounty"),
        "offers_bounty": prog["offers_bounty"],
        "phases": {p: None for p in PHASES},
        "automation_allowed": None,
        "policy_notes": "",
        "findings": [],
        "notes": [],
        "created_at": _now(),
        "updated_at": _now(),
    }


# ---------- commands ----------

def cmd_add(args) -> None:
    if load(args.handle):
        print(f"already tracking {args.handle}")
        return
    prog = fetch_program(args.handle, args.platform)
    state = new_state(prog)
    save(state)
    print(f"added: {state['platform']}/{state['handle']} — {state['name']}")
    print(f"  max_bounty: {state['max_bounty']}  status: {current_status(state)}")


def cmd_list(args) -> None:
    states = all_states()
    if args.status:
        states = [s for s in states if current_status(s) == args.status]
    if not states:
        print("(no programs tracked)")
        return
    print(f"{'HANDLE':25} {'PLATFORM':10} {'PAYOUT':>10}  {'STATUS':18}  {'FINDINGS':>8}  NAME")
    for s in states:
        payout = f"${s['max_bounty']:,}" if s.get("max_bounty") else ("paid" if s["offers_bounty"] else "VDP")
        open_findings = sum(1 for f in s["findings"] if f.get("status") != "resolved")
        print(
            f"{s['handle'][:25]:25} {s['platform']:10} {payout:>10}  "
            f"{current_status(s):18}  {open_findings:>8}  {s['name'][:40]}"
        )


def cmd_show(args) -> None:
    state = load(args.handle)
    if not state:
        sys.exit(f"not tracking {args.handle} — run `tracker.py add {args.handle}` first")
    print(f"# {state['name']}")
    print(f"Platform : {state['platform']}")
    print(f"Handle   : {state['handle']}")
    print(f"URL      : {state['program_url']}")
    print(f"Bounty   : ${state.get('min_bounty')} - ${state.get('max_bounty')}  (offers={state['offers_bounty']})")
    print(f"Status   : {current_status(state)}")
    print(f"Automation allowed: {state['automation_allowed']}")
    print()
    print("## Phases")
    for phase in PHASES:
        entry = state["phases"].get(phase)
        if entry:
            out = entry.get("output") or ""
            print(f"  [x] {phase:10} {entry['at']}  {out}")
        else:
            print(f"  [ ] {phase:10}")
    if state["policy_notes"]:
        print(f"\n## Policy notes\n{state['policy_notes']}")
    if state["findings"]:
        print(f"\n## Findings ({len(state['findings'])})")
        for f in state["findings"]:
            status = f.get("status", "open")
            print(f"  [{f['severity'][:1].upper()}/{status}] {f['title']}  — {f.get('url', '')}")
    if state["notes"]:
        print(f"\n## Notes ({len(state['notes'])})")
        for n in state["notes"][-10:]:
            print(f"  {n['at']}  {n['text']}")


def cmd_advance(args) -> None:
    state = load(args.handle)
    if not state:
        sys.exit(f"not tracking {args.handle}")
    if args.phase not in PHASES:
        sys.exit(f"unknown phase {args.phase!r} — use one of {PHASES}")
    state["phases"][args.phase] = {
        "at": _now(),
        "output": args.output,
    }
    save(state)
    print(f"{args.handle}: advanced to {args.phase}")


def cmd_note(args) -> None:
    state = load(args.handle)
    if not state:
        sys.exit(f"not tracking {args.handle}")
    state["notes"].append({"at": _now(), "text": args.text})
    save(state)
    print(f"{args.handle}: note added ({len(state['notes'])} total)")


def cmd_policy(args) -> None:
    state = load(args.handle)
    if not state:
        sys.exit(f"not tracking {args.handle}")
    mapping = {"yes": True, "no": False, "unknown": None}
    state["automation_allowed"] = mapping[args.allowed]
    if args.notes:
        state["policy_notes"] = args.notes
    state["phases"]["policy"] = {"at": _now(), "output": None}
    save(state)
    print(f"{args.handle}: policy recorded (automation_allowed={state['automation_allowed']})")


def cmd_finding(args) -> None:
    state = load(args.handle)
    if not state:
        sys.exit(f"not tracking {args.handle}")

    if args.action == "add":
        finding = {
            "id": len(state["findings"]) + 1,
            "severity": args.severity.lower(),
            "title": args.title,
            "url": args.url or "",
            "template": args.template or "",
            "status": "open",
            "at": _now(),
        }
        state["findings"].append(finding)
        save(state)
        print(f"{args.handle}: finding #{finding['id']} added ({finding['severity']}: {finding['title']})")
    elif args.action == "list":
        if not state["findings"]:
            print("(no findings)")
            return
        for f in state["findings"]:
            print(f"  #{f['id']}  [{f['severity']}/{f.get('status', 'open')}]  {f['title']}")
            if f.get("url"):
                print(f"      {f['url']}")


def cmd_discover(args) -> None:
    """Refresh program data from arkadiyt/bounty-targets-data and snapshot it to state/_catalog.json."""
    import bounties
    STATE_DIR.mkdir(exist_ok=True)
    bounties.ensure_cache(force=args.refresh)
    programs = bounties.load_all()
    by_plat: dict[str, int] = {}
    paid = 0
    for p in programs:
        by_plat[p["platform"]] = by_plat.get(p["platform"], 0) + 1
        if p["offers_bounty"]:
            paid += 1
    catalog = {
        "generated_at": _now(),
        "source": "arkadiyt/bounty-targets-data",
        "total": len(programs),
        "paid": paid,
        "by_platform": by_plat,
        "programs": programs,
    }
    CATALOG_PATH.write_text(json.dumps(catalog, indent=2, default=str) + "\n")
    print(f"catalog → {CATALOG_PATH}  ({CATALOG_PATH.stat().st_size:,} bytes)")
    print(f"  {catalog['total']} programs, {paid} paid")
    for plat, n in sorted(by_plat.items(), key=lambda x: -x[1]):
        print(f"    {plat:10} {n}")


def cmd_triage(args) -> None:
    """Score the current catalog and snapshot the ranking to state/_triage.json."""
    if not CATALOG_PATH.exists():
        sys.exit(f"no catalog — run `tracker.py discover` first")
    import triage as triage_mod
    catalog = json.loads(CATALOG_PATH.read_text())
    programs = catalog["programs"]
    scored = [triage_mod.score(p) for p in programs]
    paid = [s for s in scored if s.prog["offers_bounty"]]
    paid.sort(key=lambda s: -s.combined)

    def entry(s) -> dict:
        p = s.prog
        return {
            "platform": p["platform"],
            "handle": p["handle"],
            "name": p["name"],
            "max_bounty": p.get("max_bounty"),
            "offers_bounty": p["offers_bounty"],
            "combined": round(s.combined, 3),
            "autonomy": round(s.autonomy, 3),
            "payout_score": round(s.payout_score, 3),
            "breadth_score": round(s.breadth_score, 3),
            "competition_proxy": round(s.competition_proxy, 3),
            "has_wildcard": s.has_wildcard,
            "auto_count": s.auto_count,
            "mobile_count": s.mobile_count,
            "source_count": s.source_count,
            "hardware_count": s.hardware_count,
            "total_scope": s.total_count,
        }

    ranking = {
        "generated_at": _now(),
        "catalog_generated_at": catalog["generated_at"],
        "total_scored": len(scored),
        "paid_count": len(paid),
        "ranked": [entry(s) for s in paid],
    }
    TRIAGE_PATH.write_text(json.dumps(ranking, indent=2, default=str) + "\n")
    print(f"triage → {TRIAGE_PATH}  ({TRIAGE_PATH.stat().st_size:,} bytes)")
    print(f"  {len(paid)} paid programs scored")
    print(f"  top 5:")
    for r in ranking["ranked"][:5]:
        payout = f"${r['max_bounty']:,}" if r["max_bounty"] else "paid ($?)"
        print(f"    {r['combined']:.2f}  {r['platform']:10} {r['handle']:30}  {payout:>12}  auto-fit={r['autonomy']:.2f}")


def cmd_next(args) -> None:
    """Suggest the next action across all tracked programs, in priority order."""
    states = all_states()
    if not states:
        print("nothing tracked — add a program first")
        return

    # Priority: programs with policy review pending > passive recon pending
    # > active phases for automation_allowed=yes programs > writeup for open
    # findings. Skip automation-denied programs' active phases entirely.
    buckets: dict[str, list[tuple[dict, str]]] = {
        "review policy": [],
        "run enum": [],
        "run live": [],
        "run crawl": [],
        "run scan": [],
        "triage finding": [],
        "report": [],
    }
    for s in states:
        ph = s["phases"]
        if not ph.get("scope"):
            buckets["review policy"].append((s, f"hunt.py {s['handle']} scope"))
            continue
        if s["automation_allowed"] is None:
            buckets["review policy"].append((s, f"tracker.py policy {s['handle']} --allowed yes|no|unknown --notes '...'"))
            continue
        if s["automation_allowed"] is False:
            # passive only — still useful to enum subdomains
            if not ph.get("enum"):
                buckets["run enum"].append((s, f"hunt.py {s['handle']} enum"))
            continue
        # automation allowed
        if not ph.get("enum"):
            buckets["run enum"].append((s, f"hunt.py {s['handle']} enum"))
        elif not ph.get("live"):
            buckets["run live"].append((s, f"hunt.py {s['handle']} live"))
        elif not ph.get("crawl"):
            buckets["run crawl"].append((s, f"hunt.py {s['handle']} crawl"))
        elif not ph.get("scan"):
            buckets["run scan"].append((s, f"hunt.py {s['handle']} scan"))
        for f in s["findings"]:
            if f.get("status") == "open":
                buckets["triage finding"].append((s, f"review finding #{f['id']} on {s['handle']}: {f['title']}"))

    for action, entries in buckets.items():
        if not entries:
            continue
        print(f"\n== {action} ({len(entries)}) ==")
        for state, cmd in entries[:5]:
            print(f"  {state['handle']:25}  max=${state.get('max_bounty') or '?'}  →  {cmd}")


# ---------- cli ----------

def main() -> None:
    ap = argparse.ArgumentParser(prog="tracker", description="Per-program bounty state tracker.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("discover", help="refresh program data and snapshot catalog to state/_catalog.json")
    s.add_argument("--refresh", action="store_true", help="force re-download even if cache is fresh")
    s.set_defaults(func=cmd_discover)

    s = sub.add_parser("triage", help="score catalog and write ranking to state/_triage.json")
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("add", help="start tracking a program")
    s.add_argument("handle")
    s.add_argument("--platform", choices=("hackerone", "bugcrowd", "intigriti", "yeswehack"))
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("list", help="all tracked programs")
    s.add_argument("--status", help="filter by derived status")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("show", help="full detail for one program")
    s.add_argument("handle")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("advance", help="mark a phase done")
    s.add_argument("handle")
    s.add_argument("phase", choices=PHASES)
    s.add_argument("--output", help="path to the phase's artifact")
    s.set_defaults(func=cmd_advance)

    s = sub.add_parser("note", help="append a freeform note")
    s.add_argument("handle")
    s.add_argument("text")
    s.set_defaults(func=cmd_note)

    s = sub.add_parser("policy", help="record policy-review outcome")
    s.add_argument("handle")
    s.add_argument("--allowed", choices=("yes", "no", "unknown"), required=True)
    s.add_argument("--notes", default="", help="relevant quotes from the policy")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("finding", help="manage findings on a program")
    s.add_argument("handle")
    s.add_argument("action", choices=("add", "list"))
    s.add_argument("--severity", choices=("info", "low", "medium", "high", "critical"))
    s.add_argument("--title")
    s.add_argument("--url")
    s.add_argument("--template", help="nuclei template ID, if relevant")
    s.set_defaults(func=cmd_finding)

    s = sub.add_parser("next", help="suggest next action across all tracked programs")
    s.set_defaults(func=cmd_next)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
