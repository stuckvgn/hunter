---
description: Dashboard overview — tracked programs, their phase, open findings per program
allowed-tools: Bash(~/Desktop/hunter/tracker.py:*)
---

Run `~/Desktop/hunter/tracker.py list` and present the table. Then call out:
- programs blocked on policy review (where `automation_allowed` is still null)
- programs with open findings awaiting triage or writeup
- programs that have gone 7+ days without phase advance (check `updated_at` in state files)

Keep it brief — one screen.
