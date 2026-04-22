---
name: github-recon
description: GitHub code reconnaissance for bounty targets — subdomain discovery via GitHub code search + secret scanning via trufflehog. High-ROI per Tillson Galloway + Orwa methodology. Use when running hunt.py code_recon or investigating a target's source-code surface.
---

# github-recon

Orwa Atyat and Tillson Galloway both frame GitHub recon as the single highest-yield source of critical-severity findings in modern bounty work. "Oops commits" research (Brizinov 2024) found ~$25k in live bounties from secrets leaked in deleted forks alone.

## What hunt.py code_recon does

`hunt.py <handle> code_recon [--gh-org <org>]`:

1. For each wildcard root in `state/<handle>.json`, runs `github-subdomains -d <domain>` → discovers subdomains mentioned in GitHub code (internal/staging hosts often appear in Dockerfiles, CI configs, test data).
2. If `--gh-org <org>` is passed, runs `trufflehog github --org=<org> --only-verified` → verified live secrets in the org's public repos.

Requires `GITHUB_TOKEN` in env (falls back to `gh auth token`).

Output: `~/.cache/hunt/<handle>/code_recon/gh_subs_all.txt` (hosts) and `trufflehog_<org>.jsonl` (secrets).

## Finding the target's GitHub org

`code_recon` needs this for the trufflehog scan. Methods:

1. **Check the company's website footer** — often links `github.com/<org>`.
2. **Search GitHub** — `gh search orgs "<company name>"` or `gh search repos "<company>" --limit 20` and inspect the owner of the top repos.
3. **Inspect subdomains** — a `github.<company>.com` or `opensource.<company>.com` often redirects to their org.
4. **Package-registry**: if their JS libs publish to npm, the `homepage` / `repository` fields reveal the org.

If you can't find a canonical org, document in `tracker.py note <handle> "no public GitHub org located — trufflehog org scan skipped"` and move on.

## High-value GitHub dorks to run manually

Beyond what github-subdomains + trufflehog do automatically, these code-search queries are worth running manually:

```
org:<org> filename:.env
org:<org> filename:config.json password
org:<org> filename:docker-compose.yml
org:<org> filename:.npmrc _auth
org:<org> extension:sql "INSERT INTO"
org:<org> "BEGIN RSA PRIVATE KEY"
org:<org> "aws_access_key_id"
org:<org> filename:.travis.yml token
org:<org> filename:credentials.xml
org:<org> "api_key" OR "apikey" OR "api-key"
```

Run these via `gh search code "<query>"` or the GitHub web UI (web supports more operators).

## "Oops commits" — deleted-fork + force-push leaks

Brizinov's research: GitHub retains commits in dangling references even after they're "deleted." Use:

```bash
# Activity-stream scraping — find force-pushes and deletes
gh api repos/<org>/<repo>/events --paginate | jq '.[] | select(.type == "PushEvent" and .payload.forced == true)'
```

Then fetch the pre-force-push commit with `git fetch origin <sha>` — often contains secrets the developer thought they erased.

Specialized tool: `trufflehog github --repo=<url> --include-paths="**" --since-commit=<initial>` catches these.

## Triage: what to file

**Always file immediately (after curl-verifying the secret is live):**
- Production AWS/GCP/Azure keys
- Production Stripe/Plaid/payment-provider keys
- Production database credentials (DSN, connection string, password)
- Private SSH/GPG/TLS keys with production hostnames nearby
- GitHub PATs / fine-grained tokens granting write to the org
- CI/CD secrets (CircleCI, GitHub Actions, Jenkins) that grant deploy access

**Verify before filing:**
- Test-environment keys (often in `.env.example` with obviously fake values — not findings)
- Old keys that may have been rotated — call the service's "who am I" / `/me` endpoint first
- Secrets in forks owned by employees but not the company itself — scope check; these may be out-of-scope for the bounty

**Usually not findings:**
- Firebase API keys (not actually secrets per Firebase docs — only matter if rules are misconfigured, which is a separate bug)
- Public Google Maps / ReCAPTCHA keys
- OAuth client IDs without client secrets
- Slack webhook URLs without the corresponding tokens

## Referenced prior research

- Tillson Galloway — ["The 2025 GitHub Recon Checklist for Bug Bounty Hunters"](https://medium.com/@tillson.galloway/the-2025-github-recon-checklist-for-bug-bounty-hunters-e626ee1a1012)
- Orwa Atyat — ["Your Full Map to GitHub Recon and Leaks Exposure"](https://orwaatyat.medium.com/your-full-map-to-github-recon-and-leaks-exposure-860c37ca2c82)
- Brizinov — GitHub "oops commits" dangling-reference leaks (2024)
