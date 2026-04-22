# hunter — Claude Code operator guide

This repo is for bug-bounty work I (Claude) drive directly. Sam supervises, reviews, and gates external actions. No second LLM layer — I am the agent.

## Architecture

| Component | What |
|---|---|
| `bounties.py` | List/search 866 programs across H1/BC/INT/YWH from arkadiyt/bounty-targets-data |
| `triage.py` | Score + rank programs by autonomy × payout × scope breadth |
| `hunt.py` | Phase-based recon wrapper: scope → enum → archive → js_mine → live → crawl → param_mine → scan |
| `tracker.py` | Per-program JSON state at `state/<handle>.json`; discovery and triage write `state/_catalog.json` and `state/_triage.json` |
| `.claude/skills/` | Task-specific context I load conditionally via description matching |
| `.claude/commands/` | Slash commands I invoke: `/hunt-next`, `/hunt-add`, `/hunt-policy`, `/hunt-enum`, `/hunt-scan`, `/hunt-triage`, `/hunt-writeup`, `/hunt-status` |

## Tool inventory

On `~/.local/bin/`: `subfinder`, `httpx`, `dnsx`, `katana`, `nuclei`, `ffuf`, plus (when Move 2 installed) `gau`, `jsluice`, `subjs`, `gf`, `arjun`, and (Move 3) `trufflehog`, `github-subdomains`. SecLists at `~/.local/share/SecLists`.

System: `curl`, `wget`, `jq`, `git`, `gh` (authed as `stuckvgn`).

## Operator loop

```
/hunt-next                   # pick a target, returns a concrete next command
/hunt-add <handle>           # track a new target + pull scope
/hunt-policy <handle>        # WebFetch policy, extract rules, record automation_allowed
/hunt-enum <handle>          # passive recon (safe, no traffic to target)
/hunt-scan <handle>          # active sweep (gated on automation_allowed)
/hunt-triage <handle>        # noise-filter scan output, propose findings
/hunt-writeup <handle> <id>  # draft a report from a confirmed finding
/hunt-status                 # overview
```

Skills auto-load by description match — I don't need to Read them manually. They live in `.claude/skills/<name>/SKILL.md`.

## Safety gates (always honored)

- Never run active phases (`live`, `crawl`, `scan`, `param_mine`) unless `state/<handle>.json` has `automation_allowed: true`.
- Never submit a finding externally without Sam's explicit approval.
- Never exceed the rate limit a program's policy declares.
- Credentials aren't placeholders I fill — if a tool needs auth (e.g. `GITHUB_TOKEN` for trufflehog), check env and fail cleanly if missing.

## State files

- `state/<handle>.json` — durable per-program work state (tracked in git)
- `state/_catalog.json` — snapshot of all 866 programs from the feed (gitignored, ~10 MB)
- `state/_triage.json` — ranked scoring of all 582 paid programs (gitignored, ~267 KB)
- `~/.cache/hunt/<handle>/` — phase outputs (subs.txt, live.jsonl, nuclei.jsonl, etc.) — not in repo

## Git

Identity for commits: `126325182+stuckvgn@users.noreply.github.com` / `Sam Tucker-Davis`, passed inline (no global config). Commit + push freely; this repo is public.

## Anti-patterns to avoid

- Standing up MCP servers or LLM-framework orchestrators — they duplicate my role.
- Adding `.env` placeholders for API keys unless Sam explicitly asked.
- Committing `state/_catalog.json` or `state/_triage.json` (both derived, hourly churn).
- Human-facing markdown dashboards or manual checklist files — default output is machine-readable state.
- Auto-submitting findings (only drafts; Sam approves).
