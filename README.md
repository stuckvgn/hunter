# hunter

One repo for bug-bounty work driven by Claude (me) as the operator. Everything I need in one place: discovery CLI, triage, per-target recon harness, persistent per-program state, and the skills docs I load as context per task.

## Layout

```
hunter/
├── bounties.py          # list/search 866 programs across 4 platforms (no auth, no deps)
├── triage.py            # score + rank programs by autonomy × payout × scope breadth
├── hunt.py              # phase-based recon wrapper: scope → enum → live → crawl → scan
├── tracker.py           # persistent state machine per program
├── test_bounties.py     # 24 unittest cases, stdlib only
├── triage_output.txt    # current top-20 snapshot
├── state/               # per-program JSON state: state/<handle>.json (created by tracker)
└── skills/              # context docs I read per task — policy review, nuclei strategy,
                         # writeup format, per-platform rules
```

## Driver's workflow

A typical cycle:

```bash
# 1. Discovery + triage
./bounties.py stats                              # program counts by platform
./triage.py                                      # full ranking
./bounties.py search grafana --paid              # or pick directly

# 2. Start tracking a target
./tracker.py add kruidvat                        # fetches scope, creates state/kruidvat.json
./tracker.py show kruidvat

# 3. Passive recon (safe, third-party data)
./hunt.py kruidvat scope                         # normalize scope into ~/.cache/hunt/kruidvat/
./hunt.py kruidvat enum                          # subfinder over wildcards

# 4. Policy gate — READ skills/policy_review.md + skills/platforms/<platform>.md first,
#    fetch the program URL, extract automation clauses, then record:
./tracker.py policy kruidvat --allowed yes --notes "..."

# 5. Active phases — each a separate gated step.
./hunt.py kruidvat live
./hunt.py kruidvat crawl
./hunt.py kruidvat scan --severity high,critical --rl 20

# 6. Triage findings — skills/triage_heuristics.md before filing
./tracker.py finding kruidvat add --severity high --title "..." --url "..." --template cve-2024-xxxx

# 7. Across-program overview
./tracker.py list
./tracker.py next                                # suggests the next action, ranked
```

Every phase of `hunt.py` auto-advances the tracker if the program is tracked, so `tracker.py show <handle>` always reflects reality.

## Dependencies

Single-file, stdlib-only Python for all four scripts. Zero `pip install`.

External tools on `$PATH` (prebuilt Go binaries, no sudo):
- `subfinder` `httpx` `dnsx` `katana` `nuclei` — ProjectDiscovery
- `ffuf` — content discovery

## Data sources

Program + scope data comes from [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data), hourly-updated JSON, no auth. Four platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack. Upstream HackerOne records don't carry bounty amounts — `--min-bounty` silently excludes HackerOne.

## Testing

```bash
python3 -m unittest test_bounties -v
```

## License

Apache-2.0

## Related

- https://github.com/stuckvgn/bounties-cli — archived; original discovery CLI now lives at `bounties.py` in this repo.
- https://github.com/stuckvgn/agentic-bug-bounty-hunter — kept as reference for tool wrappers and prompt language, not used as orchestrator.
