---
description: Run passive enumeration phases (subfinder + archive + JS) — no traffic to target
argument-hint: <handle>
allowed-tools: Bash(~/Desktop/hunter/hunt.py:*), Bash(~/Desktop/hunter/tracker.py:*)
---

Handle: $ARGUMENTS

Passive phases only — no traffic to the target. Safe to run without policy review.

1. `~/Desktop/hunter/hunt.py $1 enum` — subfinder over wildcards
2. (once `archive` phase exists) `~/Desktop/hunter/hunt.py $1 archive` — gau
3. Summarize: new subdomain count, total discovered assets.

Recommend `/hunt-policy $1` next if policy phase not yet done.
