---
description: Run full active recon sweep (live + crawl + scan). Requires policy=allowed.
argument-hint: <handle>
allowed-tools: Bash(~/Desktop/hunter/hunt.py:*), Bash(~/Desktop/hunter/tracker.py:*), Bash(jq:*)
---

Handle: $ARGUMENTS

**Gate**: before running anything, read `~/Desktop/hunter/state/$1.json` and verify `automation_allowed == true`. If not, stop and explain which prior phase is missing.

Load the `nuclei-strategy` skill.

Then run, in order, checking for clean completion between each:
1. `~/Desktop/hunter/hunt.py $1 live --rl 30 -c 15`
2. `~/Desktop/hunter/hunt.py $1 crawl --rl 30 -c 15`
3. `~/Desktop/hunter/hunt.py $1 scan --severity high,critical --rl 20 -c 15`

Keep initial rate limits conservative. If the first pass shows no WAF blocks, later phases may increase `-rl`.

Report how many hits landed in each phase's output file. Suggest `/hunt-triage $1` next.
