---
description: Start tracking a bounty program — fetch scope and create state/<handle>.json
argument-hint: <handle> [--platform P]
allowed-tools: Bash(~/Desktop/hunter/tracker.py:*), Bash(~/Desktop/hunter/hunt.py:*)
---

Handle: $ARGUMENTS

1. Run `~/Desktop/hunter/tracker.py add $ARGUMENTS` to create the state file.
2. Run `~/Desktop/hunter/hunt.py $1 scope` to pull the normalized scope into `~/.cache/hunt/$1/` and auto-advance the tracker's `scope` phase.
3. Report: platform, max bounty, scope shape (urls / wildcards / other counts), top 3 in-scope targets, whether wildcards are present.
4. Suggest the next command (`/hunt-policy $1`).
