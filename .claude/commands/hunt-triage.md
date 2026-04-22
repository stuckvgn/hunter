---
description: Review scan output for real findings vs noise, file confirmed findings to tracker
argument-hint: <handle>
allowed-tools: Bash(~/Desktop/hunter/tracker.py:*), Bash(jq:*), Bash(curl:*), Read
---

Handle: $ARGUMENTS

Load the `triage-heuristics` skill and `prior-art` skill (once it exists).

1. Read `~/.cache/hunt/$1/nuclei.jsonl` and group hits by `info.severity`.
2. Apply the fast-reject rules from `triage-heuristics` — drop anything matching those patterns.
3. For each remaining hit, follow the verify-before-file sequence (curl reproduction, scope check, UA swap, duplicate check against program disclosure).
4. For each confirmed finding, propose the `tracker.py finding $1 add --severity ... --title "..." --url ... --template ...` command.

Wait for my confirmation before actually filing.
