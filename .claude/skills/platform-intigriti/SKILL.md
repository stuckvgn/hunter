---
name: platform-intigriti
description: Intigriti platform rules — scope page layout, typical automation stance, submission format, VRT-style handling, top triage picks. Load when working on an Intigriti program (handle.platform == intigriti in state).
---

# Intigriti — platform rules

European-focused platform, the least saturated of the four in our data. 127 programs, 72 paying.

## Researcher identity

Need an Intigriti account (`app.intigriti.com`). Sam's identity handles this — don't register autonomously.

## Scope page structure

Program URLs look like `https://www.intigriti.com/programs/<handle>/<handle>/detail`. The policy-relevant sections on each page:

- **Program Brief** — overall goals, vibe, manual vs automated preferences
- **Rules of Engagement** — the hard policy. Read carefully.
- **In Scope / Out of Scope** — authoritative. The arkadiyt feed is usually correct but programs sometimes update between snapshots.
- **Reward Information** — per-tier payouts.

## Typical automation stance

Most Intigriti programs tolerate rate-limited automated scanning. Common explicit rules:
- "Respect rate limits" — usually means keep concurrency moderate, no absolute number given. Treat as ~30 req/s max.
- Some programs specify nuclei/burp are allowed; others say manual only.
- DoS testing is universally out of scope.

## Submission format

Intigriti uses its own web form, not an API. Drafts should live in the tracker, and I render the human-facing version for Sam to paste into the form.

## Platform quirks

- Duplicate handling: first valid PoC wins. If a bug is already known, it's marked as duplicate with no payout — check the program's public disclosure (if any) before spending time on a finding.
- Bonus multipliers: some programs run "Hunting Parties" with 1.5–2x bounty windows. Watch the program page for announcements.
- Triage response SLAs tend to be fast (1-3 days for initial response).

## Top triage picks on Intigriti

kruidvat, iciparisxl, marionnaud, superdrug, watsons (the A.S. Watson retail cluster — likely shared infra, build recon once), uzleuven, portofantwerp, digitalocean, dropbox, capitalcom.
