# policy_review

How to read a program's policy page before running active scans.

## Fetch

```bash
# The program URL is state["program_url"] from tracker.py show <handle>.
# Use WebFetch, not curl — policy pages are usually JS-rendered.
```

Ask the fetch prompt for:
1. Automated scanning policy (any mention of "automated", "scanner", "scripting", "rate limit", "fuzzer")
2. Out-of-scope clauses that extend beyond what the scope feed carries
3. PII / data-exfil constraints (stop the moment you see real user data)
4. Bounty cap per finding, per severity
5. Required disclosure window / embargo

## Record

```bash
tracker.py policy <handle> --allowed yes|no|unknown --notes "<relevant quote>"
```

**`yes`**: policy explicitly permits automation, or is silent AND the program has >$5k max bounty (these almost always tolerate throttled scanning).
**`no`**: explicit prohibition of scanners/automation, or demand manual-only testing.
**`unknown`**: silent policy AND low-bounty program — treat as passive-only until verified by emailing the program or running an ultra-conservative probe.

## Red flags that force `--allowed no` regardless

- "no automated tools", "no scanners", "manual testing only"
- "rate limit X req/s across the entire program" — respect it or don't run
- "do not test production" when scope is clearly production
- Anything suggesting that nuclei/sqlmap/etc. submissions will be rejected or banned
- Programs mentioning WAF tuning or "triggering alerts will invalidate your findings"

## Typical clauses to quote-capture in `--notes`

- Exact rate-limit numbers
- Any out-of-band notification requirement
- Payout tier table (so `tracker.py finding --severity` maps to real money)
- Safe-harbor scope (explicit "you will not be prosecuted" language)
