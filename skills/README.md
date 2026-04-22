# skills

Domain knowledge I (Claude) load as context before or during a task. Each doc is written for me to consume — short, operational, no filler.

## Core workflow docs

- [policy_review.md](policy_review.md) — how to read a program's policy page for automation rules before running active phases
- [nuclei_strategy.md](nuclei_strategy.md) — progressive scanning approach, template severities, rate limits, what to skip
- [writeup_format.md](writeup_format.md) — structure of a finding writeup when it's ready to submit
- [triage_heuristics.md](triage_heuristics.md) — how to evaluate a raw nuclei finding for real signal vs noise

## Per-platform rules

- [platforms/intigriti.md](platforms/intigriti.md)
- [platforms/bugcrowd.md](platforms/bugcrowd.md)
- [platforms/hackerone.md](platforms/hackerone.md)
- [platforms/yeswehack.md](platforms/yeswehack.md)

## When to read which

- Before `tracker.py add <handle>` — skim the relevant platform doc.
- Before `tracker.py policy <handle>` — read `policy_review.md`, fetch the program URL, record findings.
- Before `hunt.py <handle> scan` — read `nuclei_strategy.md` so the concurrency/severity/template flags are deliberate.
- After `hunt.py <handle> scan` — read `triage_heuristics.md` before filing findings into the tracker.
- Before `tracker.py finding <handle> add` and before any submission — read `writeup_format.md`.
