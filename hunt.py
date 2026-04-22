#!/usr/bin/env python3
"""hunt — per-target bug-bounty recon harness driven directly by Claude.

Design: Claude (me) is the agent. Each phase is a single CLI command that
invokes external tools (subfinder, httpx, katana, nuclei) with safe defaults,
writes structured output under ~/.cache/hunt/<handle>/, and returns.
Phases are discrete so I review output before moving to the next and never
chain active-scanning phases without an explicit per-phase call.

Usage:
  hunt.py <handle> scope            # load scope from bounties CLI (safe)
  hunt.py <handle> enum             # subfinder — passive subdomain enum (safe)
  hunt.py <handle> live             # httpx — active: HTTP probes to target
  hunt.py <handle> crawl            # katana — active: crawl live hosts
  hunt.py <handle> scan             # nuclei — active: vuln templates
  hunt.py <handle> status           # summarize what's been done + findings
  hunt.py <handle> clear            # wipe this target's workdir

Environment:
  HUNT_DIR — override workdir root (default ~/.cache/hunt)
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

BOUNTIES_CLI = Path.home() / "Desktop" / "bounties" / "bounties.py"
HUNT_ROOT = Path(os.environ.get("HUNT_DIR", Path.home() / ".cache" / "hunt"))
ACTIVE_PHASES = {"live", "crawl", "scan"}


# ---------- workspace ----------

def workdir(handle: str) -> Path:
    d = HUNT_ROOT / handle
    d.mkdir(parents=True, exist_ok=True)
    return d


def log(handle: str, msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}"
    print(line)
    (workdir(handle) / "journal.log").open("a").write(line + "\n")


# ---------- scope ----------

def load_scope(handle: str, platform: str | None = None) -> dict:
    """Fetch normalized scope via the bounties CLI."""
    cmd = [str(BOUNTIES_CLI), "show", handle, "--json"]
    if platform:
        cmd += ["--platform", platform]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        sys.exit(f"bounties CLI failed: {r.stderr.strip() or r.stdout.strip()}")
    return json.loads(r.stdout)


def scope_targets(scope: dict) -> dict[str, list[str]]:
    """Split scope in-scope targets into url/wildcard/other buckets."""
    urls: list[str] = []
    wildcards: list[str] = []
    other: list[tuple[str, str]] = []
    for t in scope["in_scope"]:
        kind = (t.get("type") or "").lower()
        tgt = (t.get("target") or "").strip()
        if not tgt:
            continue
        if kind == "wildcard" or tgt.startswith("*."):
            wildcards.append(tgt.lstrip("*.").lstrip("."))
        elif kind in {"url", "website", "api", "web-application"} or tgt.startswith(("http://", "https://")):
            urls.append(tgt)
        else:
            other.append((kind or "?", tgt))
    return {"urls": urls, "wildcards": wildcards, "other": [f"{k}: {v}" for k, v in other]}


# ---------- phases ----------

def phase_scope(handle: str, platform: str | None) -> None:
    scope = load_scope(handle, platform)
    wd = workdir(handle)
    (wd / "scope.json").write_text(json.dumps(scope, indent=2))
    buckets = scope_targets(scope)
    (wd / "targets_urls.txt").write_text("\n".join(buckets["urls"]) + "\n" if buckets["urls"] else "")
    (wd / "targets_wildcards.txt").write_text("\n".join(buckets["wildcards"]) + "\n" if buckets["wildcards"] else "")
    (wd / "targets_other.txt").write_text("\n".join(buckets["other"]) + "\n" if buckets["other"] else "")

    log(handle, f"scope loaded: {scope['platform']}/{scope['handle']} — {scope['name']}")
    log(handle, f"  bounty: min={scope.get('min_bounty')} max={scope.get('max_bounty')} offers={scope['offers_bounty']}")
    log(handle, f"  in-scope: {len(buckets['urls'])} urls, {len(buckets['wildcards'])} wildcards, {len(buckets['other'])} other")
    log(handle, f"  out-of-scope: {len(scope['out_of_scope'])}")
    print(f"\nworkdir: {wd}")


def phase_enum(handle: str) -> None:
    """Passive subdomain enum over wildcard scope (subfinder uses third-party DNS sources)."""
    wd = workdir(handle)
    wildcards_file = wd / "targets_wildcards.txt"
    if not wildcards_file.exists() or not wildcards_file.read_text().strip():
        sys.exit("no wildcards in scope — run `hunt.py <handle> scope` first, or this program has no wildcard scope")
    out = wd / "subs.txt"
    cmd = ["subfinder", "-dL", str(wildcards_file), "-silent", "-o", str(out)]
    log(handle, f"running: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=False, text=True, check=False)
    if r.returncode != 0:
        log(handle, f"subfinder exit code {r.returncode}")
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"enum complete: {count} subdomains → {out}")


def phase_live(handle: str, concurrency: int, rate: int) -> None:
    """httpx probe — ACTIVE: sends HTTP requests to each target."""
    wd = workdir(handle)
    subs = wd / "subs.txt"
    urls = wd / "targets_urls.txt"
    combined = wd / "candidates.txt"
    lines: set[str] = set()
    if subs.exists():
        lines.update(l.strip() for l in subs.read_text().splitlines() if l.strip())
    if urls.exists():
        lines.update(l.strip() for l in urls.read_text().splitlines() if l.strip())
    if not lines:
        sys.exit("no candidates to probe — run `scope` and `enum` first")
    combined.write_text("\n".join(sorted(lines)) + "\n")

    out = wd / "live.jsonl"
    cmd = [
        "httpx",
        "-l", str(combined),
        "-silent",
        "-title", "-status-code", "-tech-detect", "-server", "-ip",
        "-json",
        "-threads", str(concurrency),
        "-rl", str(rate),
        "-o", str(out),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"live probe complete: {count} responsive hosts → {out}")


def phase_crawl(handle: str, concurrency: int, rate: int) -> None:
    """katana crawl — ACTIVE: follows links on every live host."""
    wd = workdir(handle)
    live = wd / "live.jsonl"
    if not live.exists():
        sys.exit("no live.jsonl — run `live` first")
    live_urls = wd / "live_urls.txt"
    with live.open() as fh, live_urls.open("w") as out:
        for line in fh:
            try:
                rec = json.loads(line)
                url = rec.get("url") or rec.get("input")
                if url:
                    out.write(url + "\n")
            except json.JSONDecodeError:
                continue
    out_file = wd / "katana.jsonl"
    cmd = [
        "katana",
        "-list", str(live_urls),
        "-silent",
        "-jsonl",
        "-d", "2",
        "-c", str(concurrency),
        "-rl", str(rate),
        "-o", str(out_file),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out_file.open()) if out_file.exists() else 0
    log(handle, f"crawl complete: {count} URLs → {out_file}")


def phase_scan(handle: str, concurrency: int, rate: int, severities: str) -> None:
    """nuclei template scan — ACTIVE: sends vuln-check payloads to live hosts."""
    wd = workdir(handle)
    live = wd / "live.jsonl"
    if not live.exists():
        sys.exit("no live.jsonl — run `live` first")
    live_urls = wd / "live_urls.txt"
    if not live_urls.exists():
        with live.open() as fh, live_urls.open("w") as out:
            for line in fh:
                try:
                    url = (json.loads(line).get("url") or "").strip()
                    if url:
                        out.write(url + "\n")
                except json.JSONDecodeError:
                    pass
    out = wd / "nuclei.jsonl"
    cmd = [
        "nuclei",
        "-l", str(live_urls),
        "-silent",
        "-jsonl",
        "-severity", severities,
        "-c", str(concurrency),
        "-rl", str(rate),
        "-o", str(out),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"scan complete: {count} findings → {out}")


def phase_status(handle: str) -> None:
    wd = workdir(handle)
    if not wd.exists():
        sys.exit(f"no workdir for {handle} — nothing run yet")
    files = {
        "scope.json": "scope",
        "subs.txt": "enum (subdomains)",
        "live.jsonl": "live probes",
        "katana.jsonl": "crawl",
        "nuclei.jsonl": "scan findings",
    }
    print(f"\nworkdir: {wd}\n")
    for name, label in files.items():
        p = wd / name
        if not p.exists():
            print(f"  [ ] {label:20} —")
            continue
        if name.endswith(".jsonl") or name.endswith(".txt"):
            count = sum(1 for _ in p.open())
            print(f"  [x] {label:20} {count:>6} entries    {p.stat().st_size} B")
        else:
            print(f"  [x] {label:20}              {p.stat().st_size} B")
    print()
    journal = wd / "journal.log"
    if journal.exists():
        print("recent log entries:")
        for line in journal.read_text().splitlines()[-8:]:
            print(f"  {line}")


def phase_clear(handle: str) -> None:
    wd = workdir(handle)
    if not wd.exists():
        print(f"no workdir for {handle}")
        return
    import shutil
    shutil.rmtree(wd)
    print(f"wiped {wd}")


# ---------- CLI ----------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="hunt",
        description="Per-target recon harness — each phase is an explicit step.",
    )
    ap.add_argument("handle", help="program handle (e.g. shopify, kruidvat)")
    ap.add_argument("phase", choices=["scope", "enum", "live", "crawl", "scan", "status", "clear"])
    ap.add_argument("--platform", choices=("hackerone", "bugcrowd", "intigriti", "yeswehack"),
                    help="disambiguate if handle collides")
    ap.add_argument("-c", "--concurrency", type=int, default=25, help="worker threads (active phases)")
    ap.add_argument("--rl", type=int, default=50, help="requests per second rate limit (active phases)")
    ap.add_argument("--severity", default="low,medium,high,critical",
                    help="nuclei severities, comma-separated")
    args = ap.parse_args()

    if args.phase in ACTIVE_PHASES:
        print(f"[!] {args.phase.upper()} is an ACTIVE phase — sends traffic to the target.")
        print("    Confirm the target's program policy allows automated scanning before proceeding.\n")

    phases = {
        "scope":  lambda: phase_scope(args.handle, args.platform),
        "enum":   lambda: phase_enum(args.handle),
        "live":   lambda: phase_live(args.handle, args.concurrency, args.rl),
        "crawl":  lambda: phase_crawl(args.handle, args.concurrency, args.rl),
        "scan":   lambda: phase_scan(args.handle, args.concurrency, args.rl, args.severity),
        "status": lambda: phase_status(args.handle),
        "clear":  lambda: phase_clear(args.handle),
    }
    phases[args.phase]()


if __name__ == "__main__":
    main()
