# hunt

Per-target bug-bounty recon harness. A thin Python wrapper that drives `subfinder`, `httpx`, `katana`, and `nuclei` through discrete, reviewable phases against a single program scope.

Each phase is one explicit command — no auto-chaining from passive recon into active scanning. Outputs land in `~/.cache/hunt/<handle>/` as plain files (`scope.json`, `subs.txt`, `live.jsonl`, `katana.jsonl`, `nuclei.jsonl`) so they're greppable and diffable between runs.

## Why phases are discrete

Bug bounty programs have wildly different automation policies. `scope` and `enum` are passive — they query third-party data sources (bounty targets feed, DNS aggregators). `live`, `crawl`, and `scan` send real HTTP traffic to the target and need explicit per-target authorization. Splitting them forces a human review gate between "I know what's out there" and "I'm poking it."

## Dependencies

Installed to `~/.local/bin/` (Go prebuilt binaries, no sudo needed):

- `subfinder`, `httpx`, `dnsx` (ProjectDiscovery)
- `katana` (ProjectDiscovery crawler)
- `nuclei` (ProjectDiscovery template scanner)
- `ffuf` (content discovery — used manually, not by the harness)

Program scope is fetched via the [`bounties-cli`](https://github.com/stuckvgn/bounties-cli) `show --json` command — that repo is the upstream source of truth for the normalized scope shape.

## Usage

```bash
hunt.py <handle> scope              # load + normalize program scope (safe)
hunt.py <handle> enum                # subfinder over wildcards (safe — passive)
hunt.py <handle> live                # httpx probe live hosts (ACTIVE)
hunt.py <handle> crawl               # katana crawl live hosts (ACTIVE)
hunt.py <handle> scan                # nuclei template scan (ACTIVE)
hunt.py <handle> status              # summarize current state
hunt.py <handle> clear               # wipe workdir

# flags on active phases
hunt.py <handle> live  -c 25 --rl 50
hunt.py <handle> scan  --severity medium,high,critical --rl 30
```

Override the workdir root with `HUNT_DIR=/some/path`.
