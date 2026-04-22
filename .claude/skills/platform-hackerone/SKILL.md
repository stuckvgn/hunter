---
name: platform-hackerone
description: HackerOne platform rules — scope page, Signal/Impact researcher scoring, max_severity per-asset caps, automation stance, Hacktivity for prior-art. Load when working on a HackerOne program (handle.platform == hackerone in state).
---

# HackerOne — platform rules

Most programs (455) and most competition. Payout data is NOT in the arkadiyt feed — need HackerOne API credentials to fetch per-program max_bounty.

## Researcher identity

Need a HackerOne account (`hackerone.com`). Sam's identity handles this. API credentials for authenticated scope access are separate.

## Scope page structure

URLs are `https://hackerone.com/<handle>`. Sections:
- **Policy** — the authoritative rules page
- **Scopes (Structured)** — the in/out scope with asset types and max_severity
- **Rewards** — only visible when logged in as a researcher
- **Disclosure** — public report archive for the program (read for duplicates — `prior-art` skill handles this)

## Automation stance

- HackerOne has a reputation for being stricter on scanners. Many programs explicitly ban automation or require prior approval.
- Look for "Testing restrictions" or "Out-of-scope actions" sections specifically.
- Some programs require a "test account" flag or a specific UA string. Read carefully.

## Severity — `max_severity` in the scope feed matters

Every in-scope asset has a `max_severity` (critical/high/medium/low). A low-severity asset means even a critical-class vuln on that asset is capped at low payout. Use this to prioritize — don't spend time chasing RCE on a `max_severity: low` endpoint.

## Hacktivity for prior-art

HackerOne exposes `https://hackerone.com/hacktivity` — a public stream of disclosed reports. Filter by program handle to see every publicly-disclosed finding. Use before investing in a target — load `prior-art` skill.

## Submission format

HackerOne uses markdown-friendly web forms and has an API for programmatic submission (requires `HACKERONE_API_ID` + `HACKERONE_API_TOKEN`). Never auto-submit — human review gate.

## Platform quirks

- Signal/Impact scores — HackerOne tracks per-researcher. Closing reports as Not Applicable or Duplicate lowers signal; low signal = fewer invites to private programs.
- **Top 100 leaderboard** — incentivizes quantity. Skip dupes unless they're confirmed novel.
- Bounty data missing in our feed — `triage.py` groups HackerOne into its own list, ranked on scope breadth + autonomy fit only.

## Top triage picks on HackerOne

indrive (118 auto scope + wildcard), marriott (79 + wildcard), bookingcom, mercadolibre, flutteruki, epicgames, 8x8-bounty, visa, nba-public, forescout_technologies, remitly, hyatt, hilton, pixiv, reddit.
