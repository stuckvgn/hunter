"""One-off triage script — ranks programs by autonomy-fit × payout × scope breadth.

Produces three views:
  1. Top headline — high payout + high autonomy (the main ask)
  2. Hackerone top — best-fit H1 programs (payout data is missing upstream,
     so these are ranked on autonomy + scope alone)
  3. Niche bets — smaller paying programs with specialized scope where
     hunter density is likely lower

Run: python3 triage.py
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

import bounties as b

# --- Scope classification -----------------------------------------------------
# Types empirically observed across all 45,599 in-scope targets (see
# `python3 -c 'from collections import Counter ...'` at the CLI).

FULL_AUTO = {
    "url", "wildcard", "website", "api", "web-application",
    "ip_address", "cidr", "network", "iprange",
}
SEMI_AUTO = {"other", "application", "ai_model"}
MOBILE = {
    "google_play_app_id", "apple_store_app_id", "ios", "android",
    "other_apk", "mobile-application-ios", "mobile-application-android",
    "mobile-application", "windows_app_store_app_id", "testflight", "other_ipa",
}
SOURCE = {"source_code", "downloadable_executables"}
HARDWARE = {"hardware", "iot", "smart_contract", "device"}

# Weights for each tier's contribution to autonomy score (0..1).
TIER_WEIGHT = {
    "full": 1.0,     # nuclei / nmap / ffuf / gobuster / sqlmap land here
    "semi": 0.5,     # "other" — unknown, assume partial fit
    "mobile": 0.3,   # needs mobile-specific tooling, partial autonomy
    "source": 0.2,   # code review — LLM can help but not scan
    "hardware": 0.0, # no automated tooling
}


@dataclass
class ScoredProgram:
    prog: dict
    combined: float
    autonomy: float
    payout_score: float
    breadth_score: float
    has_wildcard: bool
    payout_display: str
    auto_count: int
    mobile_count: int
    source_count: int
    hardware_count: int
    total_count: int
    competition_proxy: float  # 0 = unknown, higher = more likely competitive


def classify(scope_type: str) -> str:
    t = (scope_type or "").lower().strip()
    if t in FULL_AUTO:
        return "full"
    if t in SEMI_AUTO:
        return "semi"
    if t in MOBILE:
        return "mobile"
    if t in SOURCE:
        return "source"
    if t in HARDWARE:
        return "hardware"
    return "semi"  # unknown → assume semi


def score(prog: dict) -> ScoredProgram:
    targets = prog["in_scope"]
    types = [classify(t["type"]) for t in targets]
    counts = Counter(types)
    total = sum(counts.values()) or 1

    weighted_sum = sum(counts[tier] * TIER_WEIGHT[tier] for tier in TIER_WEIGHT)
    autonomy = weighted_sum / total

    # Payout — HackerOne dataset has no bounty amounts, so paid H1 programs
    # get a middle placeholder (0.5) instead of 0, with a display flag.
    plat = prog["platform"]
    max_b = prog.get("max_bounty") or 0
    if plat == "hackerone":
        if prog["offers_bounty"]:
            payout_score = 0.5
            payout_display = "paid ($?)"
        else:
            payout_score = 0.0
            payout_display = "VDP"
    elif max_b > 0:
        # Log-scale from $100 (0.2) to $250k (1.0).
        payout_score = min(1.0, max(0.0, (math.log10(max_b) - 2) / (math.log10(250_000) - 2)))
        payout_display = f"${max_b:,}"
    elif prog["offers_bounty"]:
        payout_score = 0.3
        payout_display = "paid"
    else:
        payout_score = 0.0
        payout_display = "VDP"

    auto_count = counts["full"]
    breadth_score = min(1.0, math.log10(max(1, auto_count) + 1) / math.log10(51))
    has_wildcard = any(t["type"] == "wildcard" for t in targets)
    wildcard_bonus = 0.08 if has_wildcard else 0

    # Competition proxy: higher max_bounty + more famous names + managed-platform
    # flags attract more hunters. We don't have hunter count, so this is weak.
    # Use log-max-bounty alone as a very rough signal.
    if max_b > 0:
        comp = min(1.0, math.log10(max_b) / math.log10(1_000_000))
    elif plat == "hackerone" and prog["offers_bounty"]:
        comp = 0.5
    else:
        comp = 0.1

    # Combined — autonomy and payout weighted equally, breadth secondary,
    # wildcard as a small bonus. Competition is NOT in the main formula;
    # it's shown separately so Sam can filter.
    combined = 0.35 * payout_score + 0.35 * autonomy + 0.22 * breadth_score + wildcard_bonus

    return ScoredProgram(
        prog=prog,
        combined=combined,
        autonomy=autonomy,
        payout_score=payout_score,
        breadth_score=breadth_score,
        has_wildcard=has_wildcard,
        payout_display=payout_display,
        auto_count=counts["full"],
        mobile_count=counts["mobile"],
        source_count=counts["source"],
        hardware_count=counts["hardware"],
        total_count=total,
        competition_proxy=comp,
    )


def row(sp: ScoredProgram) -> str:
    p = sp.prog
    label = f"{p['platform'][:4]:4} {p['handle'][:28]:28}"
    scope_mix = f"auto={sp.auto_count:>3} mob={sp.mobile_count:>2} src={sp.source_count:>2} hw={sp.hardware_count:>2}"
    wild = "W" if sp.has_wildcard else " "
    return (
        f"{sp.combined:.2f}  {label}  "
        f"{sp.payout_display:>12}  "
        f"auto-fit={sp.autonomy:.2f}  {scope_mix}  {wild}  "
        f"{p['name'][:40]}"
    )


def main() -> None:
    programs = b.load_all()
    scored = [score(p) for p in programs]

    # Exclude VDP (Sam specifically said "pays well")
    paid = [s for s in scored if s.prog["offers_bounty"]]

    # --- Headline: paid, known payout, ranked by combined ---
    known_payout = [s for s in paid if s.prog["platform"] != "hackerone"]
    known_payout.sort(key=lambda s: -s.combined)

    # --- Hackerone: paid but payout unknown, rank by autonomy+breadth ---
    h1 = [s for s in paid if s.prog["platform"] == "hackerone"]
    h1.sort(key=lambda s: -(0.5 * s.autonomy + 0.35 * s.breadth_score + (0.08 if s.has_wildcard else 0)))

    # --- Niche bets: paid ≥ $1k, auto ≥ 0.7, low-ish competition proxy,
    # AND not one of the obvious household names (heuristic: competition_proxy < 0.85).
    niche = [
        s for s in paid
        if s.autonomy >= 0.7
        and (s.prog.get("max_bounty") or 0) >= 1_000
        and s.competition_proxy < 0.85
        and s.auto_count >= 3
    ]
    niche.sort(key=lambda s: -(s.payout_score + s.autonomy + s.breadth_score - s.competition_proxy))

    def header(title):
        print("\n" + "=" * 115)
        print(title)
        print("=" * 115)
        print(f"{'SCORE':5}  {'PLAT':4} {'HANDLE':28}  {'PAYOUT':>12}  {'AUTO-FIT':8}  "
              f"{'SCOPE MIX (counts)':42}  W  NAME")
        print("-" * 115)

    header("TOP 20 HEADLINE — paid (non-HackerOne), ranked by autonomy × payout × scope breadth")
    for sp in known_payout[:20]:
        print(row(sp))

    header("TOP 15 HACKERONE — paid H1 only (payout unknown in feed), ranked by autonomy + scope breadth")
    for sp in h1[:15]:
        print(row(sp))

    header("TOP 15 NICHE BETS — auto-fit ≥ 0.7, pays ≥ $1k, lower competition proxy, ≥ 3 auto targets")
    for sp in niche[:15]:
        print(row(sp))

    print("\n" + "=" * 115)
    print("LEGEND")
    print("=" * 115)
    print("  auto-fit  = fraction of scope runnable by the agentic repo's recon tooling (nuclei/nmap/ffuf/sqlmap/etc.)")
    print("  auto      = count of in-scope targets that are url/wildcard/api/website/web-app/ip/cidr/network")
    print("  mob       = mobile targets (partial autonomy — needs emulator + dynamic analysis)")
    print("  src       = source-code review scope (LLM-assisted, not scan-autonomous)")
    print("  hw        = hardware/IoT/smart-contract scope (no automated tooling)")
    print("  W         = program has wildcard scope (subdomain-enum opportunity)")
    print("  payout    = upstream max bounty in USD; HackerOne records lack this field")
    print()
    print(f"Total paid programs considered: {len(paid)}")
    print(f"  - with known payout (BC/INT/YWH): {len(known_payout)}")
    print(f"  - HackerOne (payout unknown):     {len(h1)}")
    print(f"  - niche bets passing filter:      {len(niche)}")


if __name__ == "__main__":
    main()
