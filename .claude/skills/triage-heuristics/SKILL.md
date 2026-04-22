---
name: triage-heuristics
description: Fast-reject and fast-accept rules for raw nuclei findings, verify-before-file sequence, severity mapping from nuclei tags to real report severity. Use after hunt.py scan completes, before tracker.py finding add.
---

# triage-heuristics

Distinguishing real findings from scanner noise before filing a finding.

## Fast-reject rules — these are not findings

- Template starts with `tech-detect`, `waf-detect`, `fingerprint`, `http-missing-security-headers`, `http-title`, `robots-txt`, `sitemap-xml`, `generic-*` → informational. Don't file.
- `info` severity on a misconfig template that lists every site on the internet (e.g. `missing-sri`, `cookies-without-secure`, `cookies-without-httponly` alone) → report only as a bundle, never singly.
- The matched URL returns 403/404 now when I curl it → false positive or transient. Recheck once, then drop if still unreachable.
- The matched URL resolves to a CDN/Cloudflare error page → we matched the CDN, not the target. Drop.

## Fast-accept rules — file immediately and prioritize

- Any `exposure/` template that actually returns secret-shaped content (`.env` with non-empty values, `.git/config`, AWS keys, private JWTs) → critical or high.
- Any `cve-*` template with a CVSS ≥ 7.0 that returns a version string or response body matching the CVE signature → high/critical.
- Any `takeover/` template → critical if confirmed with curl.
- SSRF templates that return an AWS metadata 169.254.169.254 body fragment or internal IP response → critical.

## Verify-before-file

For everything in between, do this sequence:

1. **Re-request with curl** using the exact URL + method + headers the template used. Confirm the response body still contains the matched evidence.
2. **Check scope**. Open `state/<handle>.json` and verify the matched host/path is in `in_scope`, not blocked by an out-of-scope pattern. A surprising amount of nuclei output hits subdomains that have since moved out of scope.
3. **Check for duplicates** in the program's disclosure page (use WebFetch). Load `prior-art` skill first. Many top findings on enterprise programs are already known issues.
4. **Reproduce with a different user agent**. Scanners get blocked; real browsers might not. If only the scanner-UA hits, the "finding" is often a honeypot response.
5. **Only then** call `tracker.py finding <handle> add`.

## Severity mapping from nuclei to report

Nuclei's severity is a rough guide — always map to real impact when filing:

| nuclei severity | report severity | when to upgrade |
|---|---|---|
| info | don't file | never |
| low | low | if it's part of a chain → medium |
| medium | medium | if data exposure → high |
| high | high | if pre-auth + high impact → critical |
| critical | critical | stays critical |

If a "critical" template matches but the impact is limited (e.g. RCE in an isolated sandbox that has no privilege), downgrade to high and document why in the writeup.
