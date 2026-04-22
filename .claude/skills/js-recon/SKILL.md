---
name: js-recon
description: JavaScript reconnaissance — extracting URLs, API paths, and hardcoded secrets from JS bundles. Use when working on targets with rich JS (SPA / SaaS apps) or when hunt.py js_mine has produced js_findings.jsonl that needs interpretation.
---

# js-recon

Top bug-bounty hunters rank JS mining as the single highest-ROI phase after live-host discovery. Unminified JS bundles leak API routes, customer IDs, IAM keys, Firebase configs, Stripe keys, and feature flags that never appear in crawled HTML.

## What hunt.py js_mine does

`hunt.py <handle> js_mine` runs after `live`. It:

1. Feeds `live_urls.txt` to `subjs` → discovers every `.js` URL referenced by the live host set.
2. Fetches up to 200 JS files (cap to keep a run bounded).
3. Regex-scans each for:
   - **Secrets**: AWS access keys (`AKIA...`), Google API keys (`AIza...`), GitHub tokens (`ghp_...`), Stripe live keys (`sk_live_...` / `pk_live_...`), Slack tokens, JWTs, Firebase config blocks, private key headers, Mailgun keys, Twilio SIDs.
   - **URLs**: absolute `https?://...`
   - **API paths**: quoted paths starting `/api/`, `/v1/`, `/internal/`, `/admin/`, `/debug/`, `/graphql`, `/oauth/`, `/auth/`, `/rest/`.

Output: `~/.cache/hunt/<handle>/js_findings.jsonl` (one JSON record per match).

## Caveats — I'm using regex, not AST parsing

The BishopFox `jsluice` tool does this with tree-sitter AST parsing, which catches:
- Concatenated strings (`"https://" + host + "/api"`)
- Base64-encoded constants
- Deeply obfuscated webpack bundles

My regex miner misses those. For high-value targets with heavily minified JS, consider installing jsluice once a C toolchain is available (needs `sudo apt install build-essential` then `go install github.com/BishopFox/jsluice/cmd/jsluice@latest`). Until then, regex covers unminified customer-facing SPAs well.

## Triage: what's signal vs noise

### Always-real hits (file as critical-or-high immediately)

- `aws_access_key` + adjacent `aws_secret` key in same file (pattern within ~100 chars)
- `github_token`, `gho_`, `ghu_`, `ghs_`, `ghr_` — any personal or fine-grained GitHub token → **test with `curl -H "Authorization: token ..."`** to confirm it's live before filing
- `stripe_live_sk` — live Stripe secret keys are critical (ignore `sk_test_`)
- `private_key_header` with actual key body below
- Firebase config with `databaseURL` + unauthenticated write access (test with `curl PATCH` to the URL)

### Usually noise (don't file)

- JWTs found in JS — usually short-lived demo tokens baked in for local dev; verify by decoding the `exp` claim. Only file if `exp` is in the future AND the token grants server-side access (not a client-only identity token).
- Slack webhook URLs in CI/debug config — low severity unless actively exploitable for spam
- Firebase API keys alone are **not secrets** per Firebase docs — they need to be combined with misconfigured security rules.
- Google Maps API keys — usually public-by-design. Only file if they lack referrer restrictions AND you can demonstrate paid API call abuse.

## Common high-signal API paths to prioritize

When `js_findings.jsonl` has `type: api_path`, prioritize these patterns for manual follow-up:

- `/internal/*` — explicit internal endpoints that shouldn't be reachable
- `/admin/*` — admin panels; check IDOR and missing auth
- `/graphql` — likely introspection-enabled; dump schema with `curl -X POST -d '{"query":"query IntrospectionQuery { __schema { types { name } } }"}'`
- `/debug/*` — often exposes heapdumps, env vars, stack traces
- `/oauth/*` — check for missing state params, open redirects in `redirect_uri`, client_id enumeration

## Source maps — the holy grail

If a JS file's response includes `//# sourceMappingURL=...` at the bottom, fetch that `.js.map` file. Source maps contain original unminified source and sometimes full server-side code. Grep for them:

```bash
jq -r 'select(.type=="absolute_url") | .url' js_findings.jsonl | grep -i "\.map$" | sort -u
```

Then fetch and look at `sources` and `sourcesContent` fields — they may contain full developer code.

## Next steps after js_mine

1. Review `js_findings.jsonl` for any `secret` records — triage + file any confirmed live secrets.
2. Deduplicate extracted URLs/paths and merge into the corpus feeding `param_mine` and `scan`:
   ```bash
   jq -r 'select(.type=="absolute_url") | .url' js_findings.jsonl >> live_urls.txt
   jq -r 'select(.type=="api_path") | .path' js_findings.jsonl | sort -u > extracted_paths.txt
   ```
3. Re-run `param_mine` with the enlarged corpus.
