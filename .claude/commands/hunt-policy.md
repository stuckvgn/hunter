---
description: Fetch a program's policy page, extract automation rules, record into tracker
argument-hint: <handle>
allowed-tools: Bash(~/Desktop/hunter/tracker.py:*), WebFetch
---

Handle: $ARGUMENTS

Load the `policy-review` skill and the platform-specific skill (`platform-intigriti`, `platform-bugcrowd`, `platform-hackerone`, or `platform-yeswehack` — decide from the `platform` field in `~/Desktop/hunter/state/$1.json`).

Then:
1. Read `state/$1.json` to get `program_url`.
2. WebFetch that URL with a prompt asking for: automation policy, out-of-scope clauses, PII constraints, payout tiers, rate limits, safe-harbor language.
3. Decide `--allowed yes|no|unknown` per the rules in the `policy-review` skill.
4. Propose the `tracker.py policy $1 --allowed ... --notes "..."` command with the quote-captured notes.

Stop before running the tracker command — let me review and confirm the quotes.
