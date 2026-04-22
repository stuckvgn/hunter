#!/usr/bin/env python3
"""List open bug bounty programs from the arkadiyt/bounty-targets-data dataset.

Covers HackerOne, Bugcrowd, Intigriti, YesWeHack. No authentication required —
data is fetched from public JSON dumps updated hourly on GitHub.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable

DATA_BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data"
PLATFORMS = ("hackerone", "bugcrowd", "intigriti", "yeswehack")
CACHE_DIR = Path(os.environ.get("BOUNTIES_CACHE_DIR", Path.home() / ".cache" / "bounties-cli"))
CACHE_TTL_SECONDS = 24 * 60 * 60


# ---------- fetching / caching ----------

def cache_path(platform: str) -> Path:
    return CACHE_DIR / f"{platform}_data.json"


def fetch_platform(platform: str) -> None:
    url = f"{DATA_BASE}/{platform}_data.json"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "bounties-cli"})
    with urllib.request.urlopen(req, timeout=60) as r:
        cache_path(platform).write_bytes(r.read())


def ensure_cache(force: bool = False) -> None:
    for p in PLATFORMS:
        path = cache_path(p)
        stale = not path.exists() or (time.time() - path.stat().st_mtime) > CACHE_TTL_SECONDS
        if force or stale:
            print(f"fetching {p}...", file=sys.stderr)
            fetch_platform(p)


def load_platform(platform: str) -> list[dict]:
    path = cache_path(platform)
    if not path.exists():
        fetch_platform(platform)
    return json.loads(path.read_text())


# ---------- normalization ----------
# Each upstream platform has a different schema. Collapse to a shared shape
# so filtering and display can stay platform-agnostic.

def _norm_hackerone(rec: dict) -> dict:
    targets = rec.get("targets") or {}
    return {
        "platform": "hackerone",
        "handle": rec["handle"],
        "name": rec["name"],
        "url": rec["url"],
        "website": rec.get("website"),
        "offers_bounty": bool(rec.get("offers_bounties")),
        "min_bounty": None,
        "max_bounty": None,
        "in_scope": [
            {
                "type": (t.get("asset_type") or "").lower(),
                "target": t.get("asset_identifier"),
                "severity": t.get("max_severity"),
                "eligible_for_bounty": t.get("eligible_for_bounty"),
                "note": t.get("instruction"),
            }
            for t in targets.get("in_scope", [])
        ],
        "out_of_scope": [
            {"type": (t.get("asset_type") or "").lower(), "target": t.get("asset_identifier")}
            for t in targets.get("out_of_scope", [])
        ],
    }


def _norm_bugcrowd(rec: dict) -> dict:
    targets = rec.get("targets") or {}
    handle = rec["url"].rstrip("/").rsplit("/", 1)[-1]
    max_payout = rec.get("max_payout") or 0
    return {
        "platform": "bugcrowd",
        "handle": handle,
        "name": rec["name"].strip(),
        "url": rec["url"],
        "website": None,
        "offers_bounty": bool(max_payout and max_payout > 0),
        "min_bounty": None,
        "max_bounty": max_payout or None,
        "in_scope": [
            {"type": (t.get("type") or "").lower(), "target": t.get("target") or t.get("uri"), "note": t.get("name")}
            for t in targets.get("in_scope", [])
        ],
        "out_of_scope": [
            {"type": (t.get("type") or "").lower(), "target": t.get("target") or t.get("uri")}
            for t in targets.get("out_of_scope", [])
        ],
    }


def _norm_intigriti(rec: dict) -> dict:
    targets = rec.get("targets") or {}
    mn = (rec.get("min_bounty") or {}).get("value")
    mx = (rec.get("max_bounty") or {}).get("value")
    return {
        "platform": "intigriti",
        "handle": rec["handle"],
        "name": rec["name"],
        "url": rec["url"],
        "website": None,
        "offers_bounty": bool(mx and mx > 0),
        "min_bounty": mn or None,
        "max_bounty": mx or None,
        "in_scope": [
            {
                "type": (t.get("type") or "").lower(),
                "target": t.get("endpoint"),
                "note": t.get("description"),
                "tier": t.get("impact"),
            }
            for t in targets.get("in_scope", [])
        ],
        "out_of_scope": [
            {"type": (t.get("type") or "").lower(), "target": t.get("endpoint")}
            for t in targets.get("out_of_scope", [])
        ],
    }


def _norm_yeswehack(rec: dict) -> dict:
    targets = rec.get("targets") or {}
    return {
        "platform": "yeswehack",
        "handle": rec["id"],
        "name": rec["name"],
        "url": f"https://yeswehack.com/programs/{rec['id']}",
        "website": None,
        "offers_bounty": bool(rec.get("max_bounty")),
        "min_bounty": rec.get("min_bounty") or None,
        "max_bounty": rec.get("max_bounty") or None,
        "in_scope": [
            {"type": (t.get("type") or "").lower(), "target": t.get("target")}
            for t in targets.get("in_scope", [])
        ],
        "out_of_scope": [
            {"type": (t.get("type") or "").lower(), "target": t.get("target")}
            for t in targets.get("out_of_scope", [])
        ],
    }


NORMALIZERS = {
    "hackerone": _norm_hackerone,
    "bugcrowd": _norm_bugcrowd,
    "intigriti": _norm_intigriti,
    "yeswehack": _norm_yeswehack,
}


def load_all(platforms: Iterable[str] | None = None) -> list[dict]:
    selected = tuple(platforms) if platforms else PLATFORMS
    out: list[dict] = []
    for p in selected:
        out.extend(NORMALIZERS[p](rec) for rec in load_platform(p))
    return out


# ---------- filtering ----------

def apply_filters(
    programs: list[dict],
    *,
    platforms: Iterable[str] | None = None,
    paid_only: bool = False,
    vdp_only: bool = False,
    min_max_bounty: int | None = None,
    scope_types: Iterable[str] | None = None,
    keyword: str | None = None,
) -> list[dict]:
    out = programs
    if platforms:
        plats = set(platforms)
        out = [p for p in out if p["platform"] in plats]
    if paid_only:
        out = [p for p in out if p["offers_bounty"]]
    if vdp_only:
        out = [p for p in out if not p["offers_bounty"]]
    if min_max_bounty is not None:
        out = [p for p in out if (p.get("max_bounty") or 0) >= min_max_bounty]
    if scope_types:
        stypes = {s.lower() for s in scope_types}
        out = [p for p in out if any((t.get("type") or "") in stypes for t in p["in_scope"])]
    if keyword:
        k = keyword.lower()
        def matches(p: dict) -> bool:
            if k in p["name"].lower() or k in p["handle"].lower():
                return True
            return any(k in (t.get("target") or "").lower() for t in p["in_scope"])
        out = [p for p in out if matches(p)]
    return out


# ---------- display ----------

def fmt_bounty(p: dict) -> str:
    if not p["offers_bounty"]:
        return "VDP"
    mn, mx = p.get("min_bounty"), p.get("max_bounty")
    if mn and mx:
        return f"${mn}-${mx}"
    if mx:
        return f"up to ${mx}"
    return "paid"


def print_header() -> None:
    print(f"{'PLATFORM':10} {'HANDLE':35} {'BOUNTY':14} SCOPE  NAME")


def print_row(p: dict) -> None:
    print(
        f"{p['platform']:10} "
        f"{p['handle'][:35]:35} "
        f"{fmt_bounty(p):14} "
        f"{len(p['in_scope']):5}  "
        f"{p['name'][:60]}"
    )


def print_show(p: dict) -> None:
    print(f"# {p['name']}")
    print(f"Platform : {p['platform']}")
    print(f"Handle   : {p['handle']}")
    print(f"URL      : {p['url']}")
    if p.get("website"):
        print(f"Website  : {p['website']}")
    print(f"Bounty   : {fmt_bounty(p)}")
    print()
    print(f"## In scope ({len(p['in_scope'])})")
    for t in p["in_scope"]:
        line = f"  [{t.get('type') or '?'}] {t.get('target')}"
        if t.get("severity"):
            line += f"  (max: {t['severity']})"
        if t.get("tier"):
            line += f"  ({t['tier']})"
        print(line)
        note = t.get("note")
        if note and len(note) < 240:
            print(f"      - {note}")
    oos = p["out_of_scope"]
    if oos:
        print()
        print(f"## Out of scope ({len(oos)})")
        for t in oos[:20]:
            print(f"  [{t.get('type') or '?'}] {t.get('target')}")
        if len(oos) > 20:
            print(f"  ... and {len(oos) - 20} more")


def dump_json(programs: list[dict]) -> None:
    json.dump(programs, sys.stdout, indent=2, default=str)
    print()


# ---------- commands ----------

def cmd_update(args) -> None:
    ensure_cache(force=True)
    print(f"cache updated: {CACHE_DIR}")


def cmd_stats(args) -> None:
    ensure_cache()
    programs = load_all()
    by_platform: dict[str, int] = {}
    paid = 0
    for p in programs:
        by_platform[p["platform"]] = by_platform.get(p["platform"], 0) + 1
        if p["offers_bounty"]:
            paid += 1
    print(f"Total programs : {len(programs)}")
    print(f"Paid bounty    : {paid}")
    print(f"VDP (no pay)   : {len(programs) - paid}")
    print()
    print("By platform:")
    for plat, n in sorted(by_platform.items(), key=lambda x: -x[1]):
        plat_progs = [p for p in programs if p["platform"] == plat]
        plat_paid = sum(1 for p in plat_progs if p["offers_bounty"])
        print(f"  {plat:12} {n:4} total  {plat_paid:4} paid")


def _filter_from_args(programs, args, keyword=None) -> list[dict]:
    return apply_filters(
        programs,
        platforms=args.platform,
        paid_only=args.paid,
        vdp_only=args.vdp,
        min_max_bounty=args.min_bounty,
        scope_types=args.scope_type,
        keyword=keyword,
    )


def _sort(programs: list[dict]) -> list[dict]:
    return sorted(
        programs,
        key=lambda p: (not p["offers_bounty"], -(p.get("max_bounty") or 0), p["name"].lower()),
    )


def cmd_list(args) -> None:
    ensure_cache()
    programs = _sort(_filter_from_args(load_all(args.platform), args, keyword=args.keyword))
    if args.limit:
        programs = programs[: args.limit]
    if args.json:
        dump_json(programs)
        return
    print_header()
    for p in programs:
        print_row(p)
    print(f"\n{len(programs)} programs")


def cmd_show(args) -> None:
    ensure_cache()
    programs = load_all()
    handle = args.handle.lower()
    exact = [
        p for p in programs
        if p["handle"].lower() == handle and (args.platform is None or p["platform"] == args.platform)
    ]
    if not exact:
        partial = [p for p in programs if handle in p["handle"].lower() or handle in p["name"].lower()]
        print(f"No program with handle {args.handle!r}", file=sys.stderr)
        if partial:
            print("Closest matches:", file=sys.stderr)
            for p in partial[:10]:
                print(f"  {p['platform']}/{p['handle']}  ({p['name']})", file=sys.stderr)
        sys.exit(1)
    if len(exact) > 1:
        print(f"Multiple matches for {args.handle!r} — pass --platform:", file=sys.stderr)
        for p in exact:
            print(f"  {p['platform']}/{p['handle']}  ({p['name']})", file=sys.stderr)
        sys.exit(1)
    if args.json:
        print(json.dumps(exact[0], indent=2, default=str))
    else:
        print_show(exact[0])


def cmd_search(args) -> None:
    ensure_cache()
    programs = _sort(_filter_from_args(load_all(), args, keyword=args.query))
    if args.limit:
        programs = programs[: args.limit]
    if args.json:
        dump_json(programs)
        return
    print_header()
    for p in programs:
        print_row(p)
    print(f"\n{len(programs)} matches for {args.query!r}")


# ---------- argparse wiring ----------

def _add_filter_flags(sp) -> None:
    sp.add_argument("--platform", nargs="+", choices=PLATFORMS, help="limit to one or more platforms")
    sp.add_argument("--paid", action="store_true", help="only programs that pay bounties")
    sp.add_argument("--vdp", action="store_true", help="only VDP (non-paying) programs")
    sp.add_argument("--min-bounty", type=int, metavar="USD", help="only programs whose max_bounty is at least this")
    sp.add_argument("--scope-type", nargs="+", metavar="TYPE", help="only programs with at least one in-scope target of these types (url, api, android, ios, ...)")
    sp.add_argument("--limit", type=int, help="cap number of results")
    sp.add_argument("--json", action="store_true", help="emit normalized JSON")


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="bounties",
        description="List open bug bounty programs (HackerOne, Bugcrowd, Intigriti, YesWeHack).",
    )
    subs = ap.add_subparsers(dest="cmd", required=True)

    s = subs.add_parser("list", help="list programs (with filters)")
    _add_filter_flags(s)
    s.add_argument("--keyword", help="filter by keyword in name/handle/in-scope targets")
    s.set_defaults(func=cmd_list)

    s = subs.add_parser("show", help="show one program's full scope")
    s.add_argument("handle", help="program handle, e.g. github / uber / shopify")
    s.add_argument("--platform", choices=PLATFORMS, help="disambiguate if the handle collides")
    s.add_argument("--json", action="store_true", help="emit normalized JSON")
    s.set_defaults(func=cmd_show)

    s = subs.add_parser("search", help="keyword search across name, handle, and in-scope targets")
    s.add_argument("query", help="keyword, e.g. 'github', 'api.example.com', 'ios'")
    _add_filter_flags(s)
    s.set_defaults(func=cmd_search)

    s = subs.add_parser("update", help="force refresh of cached program data")
    s.set_defaults(func=cmd_update)

    s = subs.add_parser("stats", help="summary counts per platform")
    s.set_defaults(func=cmd_stats)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
