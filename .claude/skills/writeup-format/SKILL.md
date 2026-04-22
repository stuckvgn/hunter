---
name: writeup-format
description: Required fields and order for a bug-bounty report (title, severity, summary, affected assets, reproduction, PoC, impact, remediation). Severity calibration table. Pre-submit checklist. Use when drafting a finding for Sam review.
---

# writeup-format

Structure of a bug bounty report before I show it to Sam for sign-off.

## Required fields (in this order)

1. **Title** — `<vuln type> in <component> via <vector>`. Specific, not "Security Issue in Website".
2. **Severity** — CVSS v3.1 vector string + derived score + label (info/low/medium/high/critical).
3. **Summary** — 2-3 sentences. What's broken, what an attacker can do, why it matters to the business.
4. **Affected assets** — exact URL(s), parameter names, request methods. Must map to the program's in-scope list.
5. **Steps to reproduce** — numbered, copy-pasteable curl/request commands. Every step independently verifiable.
6. **Proof of concept** — raw request + raw response with the evidence highlighted. Screenshot only if the evidence is visual (e.g. rendered XSS).
7. **Impact** — what concretely happens in the worst realistic case. Tie to business, not CWE theory.
8. **Suggested remediation** — specific, not "add validation". Example: "whitelist `\[A-Za-z0-9-_\]+` on the `redirect_to` param."
9. **References** — CWE ID, OWASP category, any related CVE if applicable.

## Optional but strong

- **Attack chain** — if this finding combines with another open finding for higher impact, show the chain.
- **Variants** — other URLs/params where the same root cause applies; include them to inflate bounty tier and prevent duplicate rejection.

## What NOT to include

- Nuclei template output verbatim — rephrase. Programs reject copy-pasted tool output.
- Speculation ("this might allow RCE if..."). Only confirmed impact.
- CVSS "temporal" or "environmental" — stick to Base Score; triage teams resent padding.
- Marketing language ("this critical issue") — just facts.

## Severity calibration

- **Critical**: pre-auth RCE, mass PII dump, account takeover without interaction.
- **High**: auth bypass, SSRF to internal network, stored XSS in auth'd view, SQLi with data extraction.
- **Medium**: IDOR with limited reach, reflected XSS, open redirect chained to credential phishing, CSRF on sensitive action.
- **Low**: info disclosure without direct exploitation, CORS misconfig with no session cookies.
- **Info**: version disclosures, missing headers in isolation, anything without clear demonstrated impact.

Overclaiming severity = slower triage + reputation damage on the platform.

## Pre-submit checklist

- [ ] Affected URLs are in-scope (cross-checked against `state/<handle>.json`)
- [ ] Reproduced with a freshly-created test account (not privileged)
- [ ] No third-party data was accessed beyond what's necessary to demonstrate impact
- [ ] Working PoC doesn't leave permanent side-effects (no defacement, no persisted XSS payloads, no created objects not tagged as test)
- [ ] `tracker.py finding <handle> add` records the draft with `--severity` and `--url`
- [ ] Sam has reviewed and approved submission (gate — never auto-submit)
