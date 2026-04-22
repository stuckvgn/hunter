---
name: nuclei-strategy
description: Progressive nuclei scan order (exposures → CVEs → misconfig → tech-specific → generic), flags I always/never pass, gf-pattern prefiltering. Use when planning or running hunt.py scan phase.
---

# nuclei-strategy

Running nuclei against a live target set discovered by `hunt.py live`.

## Progressive sweep

Never run the full template set at max concurrency on the first pass. Order:

1. **Exposures** — hardcoded secrets in repo files, `/debug`, admin panels, `.git`, `.env`, backup files. Low traffic, high signal.
   ```bash
   nuclei -l live_urls.txt -tags exposure -rl 20 -c 15 -jsonl -o exposures.jsonl
   ```

2. **CVEs** — known-CVE templates. Moderate traffic, very high signal when a hit.
   ```bash
   nuclei -l live_urls.txt -tags cve -severity high,critical -rl 30 -c 20 -jsonl -o cves.jsonl
   ```

3. **Misconfigurations** — HTTP headers, SSL, TLS, CORS.
   ```bash
   nuclei -l live_urls.txt -tags misconfig -severity medium,high,critical -rl 30 -c 20 -jsonl -o misconfig.jsonl
   ```

4. **Tech-specific** — after httpx's `-tech-detect` output tells me what's running. E.g. if nginx:
   ```bash
   nuclei -l live_urls.txt -tags nginx -rl 30 -c 20 -jsonl -o tech_nginx.jsonl
   ```

5. **Generic vulns** (SSRF/XSS/SQLI templates) — highest traffic, most false positives, run last. **Feed gf-filtered URL subsets** (see below) rather than the full live_urls list.
   ```bash
   gf ssrf  < all_urls.txt > ssrf_candidates.txt
   nuclei -l ssrf_candidates.txt -tags ssrf -severity medium,high,critical -rl 20 -c 15 -jsonl -o ssrf.jsonl
   ```

## gf prefilter — use this before step 5

`gf` applies named regex patterns to an URL corpus (from katana crawl + gau archive + param_mine). It cuts the generic-vuln template volume dramatically by running each template class only against URLs likely to carry that vuln class:

- `gf ssrf`  → URLs with redirect-shaped params (`url=`, `target=`, `dest=`, `next=`, `redirect=`)
- `gf lfi`   → URLs with path-traversal-shaped params
- `gf xss`   → URLs with reflected-param candidates
- `gf ssti`  → URLs where template syntax could be evaluated
- `gf idor`  → URLs with numeric ID params
- `gf redirect` → redirect-chain candidates

This converts "run xss templates against 5000 URLs" (noisy, slow) into "run xss templates against the 200 URLs that actually have reflected params."

## Flags I always pass

- `-rl <N>` rate limit — never exceed the policy's stated rate
- `-c <N>` concurrency — 15-25 is plenty for most targets
- `-jsonl` — machine-parseable output
- `-silent` — cleaner logs
- `-severity` — usually skip `info` and `unknown` unless explicitly asked

## Flags I should almost never pass

- `-as` (automatic scan) — throws everything at once; don't
- `-headless` — costs 10× the traffic
- `-fuzz` — it fuzzes parameters; high traffic and often out-of-scope for scanner policies

## After scan: review before filing to tracker

Run `jq '.info.name + " — " + .info.severity + " — " + .matched_at' nuclei.jsonl` to scan the hits. For each, ask:

1. Is the template ID famously noisy? (`tech-detect`, `generic-apis`, `waf-detect` are not vulns)
2. Does the matched-at URL correspond to an in-scope target, or did we follow a redirect off-scope?
3. Is the finding reproducible with curl? If not, the template matched noise.

Only file real findings via `tracker.py finding <handle> add`. Load `triage-heuristics` skill before filing.
