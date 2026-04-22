---
name: prior-art
description: Check a target's public disclosure history before investing — what's already been found, what vuln classes the team has systematically fixed, observed median payout. Use before starting a new target, and again before filing any specific finding (dup check).
---

# prior-art

Jason Haddix and zseano frame prior-art review as "reading the changelog before you start hacking." You learn:

1. What's already been found on this target (duplicate risk)
2. What vuln classes the team has systematically fixed (dead zones — don't spend time there)
3. What they actually pay, not what their policy claims (payout distribution → real expected value)

## Where public disclosures live, per platform

| Platform | URL pattern | Notes |
|---|---|---|
| HackerOne | `https://hackerone.com/hacktivity?querystring=team%3A<handle>` | Filter by team handle. Only public reports show. |
| Bugcrowd | `https://bugcrowd.com/programs/<handle>/disclosures` | Some programs disclose, many don't |
| Intigriti | program page → "Public disclosure" tab, if enabled | Sparse |
| YesWeHack | `https://yeswehack.com/programs/<id>/changelog` | Also sparse |

Also useful (cross-program):
- [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) — scraped corpus of all HackerOne disclosed reports, searchable offline
- [Bugcrowd Crowdstream](https://bugcrowd.com/crowdstream) — recent disclosures across all Bugcrowd programs

## Pre-target check (do before investing time)

For a new target:

1. **WebFetch the platform's disclosure URL** for the program handle. Prompt: "List every publicly disclosed vulnerability for this program: title, severity, vuln class (XSS/SSRF/IDOR/etc.), bounty paid if stated, date."
2. **Summarize into tracker as notes**:
   ```bash
   tracker.py note <handle> "disclosure: 12 reports, mostly XSS + IDOR; observed median bounty $2500 (stated max: $10000); no SSRF/RCE/auth-bypass disclosed → those classes likely unexplored"
   ```
3. **Calibrate expectation**: observed median payout is a better signal than stated max. If median is $500 on a $10k-max program, actual payouts run low.
4. **Flag dead zones**: if 80% of disclosed reports are the same class, assume the team has systematic defenses there. Skip that class.
5. **Flag live zones**: vuln classes conspicuously absent from disclosure are either (a) well-defended, or (b) unexplored. Investigate.

## Pre-submit check (do before filing any specific finding)

For a specific finding you're about to submit:

1. Search the program's disclosure page for the finding's vuln class + affected asset. WebFetch + prompt: "Does this program have any disclosed report involving $ASSET and $VULN_CLASS?"
2. If yes, read that report carefully. Is it the same bug? Different instance of the same root cause? A fix that didn't cover this variant?
3. If it's a clear duplicate → don't submit. Duplicate submissions cost signal on HackerOne and reputation on Bugcrowd.
4. If it's a similar but distinct finding (different URL, different parameter, different root cause) → reference the prior report in your writeup: "Similar to report #XXXX but affects a different endpoint and has a different fix path."

## Record outcomes in state

After prior-art review, update `tracker.py`:

```bash
tracker.py note <handle> "prior-art: reviewed <N> disclosed reports at <url>. observed median bounty $X. dead zones: <classes>. live zones: <classes>."
```

Then `tracker.py advance <handle> prior_art`.

## Tooling shortcut

For HackerOne specifically, the hacktivity page supports URL filters. Example:

```
https://hackerone.com/hacktivity?queryString=team%3A<handle>%20disclosed%3Atrue&sortField=disclosed_at&sortDirection=DESC
```

WebFetch that URL for any H1 program handle to get the ~50 most recent disclosed reports in one shot.
