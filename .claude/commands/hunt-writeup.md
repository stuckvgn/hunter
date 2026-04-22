---
description: Draft a structured writeup for a specific finding on a tracked program
argument-hint: <handle> <finding-id>
allowed-tools: Bash(~/Desktop/hunter/tracker.py:*), Write(~/Desktop/hunter/findings/**)
---

Handle: $1
Finding ID: $2

Load the `writeup-format` skill and the platform skill for $1.

1. Pull the finding record from `~/Desktop/hunter/state/$1.json` (finding id $2).
2. Draft the report using the exact section order from `writeup-format`. No speculation; no marketing language.
3. Save the draft to `~/Desktop/hunter/findings/$1/$2.md`.
4. Walk through the pre-submit checklist from `writeup-format` and flag any unchecked items.

Never submit — human gate (me/Sam) must approve before any external submission.
