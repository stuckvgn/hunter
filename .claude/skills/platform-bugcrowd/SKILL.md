---
name: platform-bugcrowd
description: Bugcrowd platform rules — MBB vs public vs invite, scope page layout, VRT severity framework, automation stance, top triage picks. Load when working on a Bugcrowd program (handle.platform == bugcrowd in state).
---

# Bugcrowd — platform rules

Second-biggest platform in our dataset. 214 programs, 209 paying. More competition than Intigriti but higher ceilings.

## Researcher identity

Need a Bugcrowd Crowdcontrol account. Sam's identity handles this.

## Program types

- **Managed Bug Bounty (MBB)** — platform-operated, higher hunter traffic, handle contains `-mbb`. Examples: t-mobile, etoro-mbb-og, aiven-mbb-og.
- **Public** — self-managed by the client, variable triage quality.
- **Private / Invitational** — by invite only. Handle often ends in `-invite` or `-private`. Example: sap-private-invite ($20k max).

## Scope page structure

URLs are `https://bugcrowd.com/engagements/<handle>`. Sections to read:
- **Brief** — usually the "what we care about" summary
- **Targets** — in/out scope with severity ceilings per target
- **Rewards** — explicit tier table
- **Program Rules** — the authoritative policy

## Automation stance

- The words "you may use automated scanners" appear on many programs — read for it.
- Bugcrowd's default posture is more scanner-tolerant than HackerOne but still expects throttled traffic.
- **"VRT"** (Vulnerability Rating Taxonomy) — Bugcrowd's canonical severity framework. Use its categories when filing, not CWE IDs alone.

## Submission format

Bugcrowd submissions use their web UI, following the VRT. Tracker's `finding` records map 1:1 to VRT categories.

## Platform quirks

- Triage can be slower than Intigriti — weeks not days.
- Payouts are in USD unless specified otherwise.
- Opensea ($3M), Fireblocks ($250k), T-Mobile ($133k) — the top payouts on Bugcrowd. High competition.
- SpaceX ($100k, 1 scope item) — sounds great but only 1 in-scope target means the surface is minute; probably already heavily tested.
