#!/usr/bin/env python3
"""hunt — per-target bug-bounty recon harness driven directly by Claude.

Design: Claude (me) is the agent. Each phase is a single CLI command that
invokes external tools (subfinder, httpx, katana, nuclei) with safe defaults,
writes structured output under ~/.cache/hunt/<handle>/, and returns.
Phases are discrete so I review output before moving to the next and never
chain active-scanning phases without an explicit per-phase call.

Usage:
  hunt.py <handle> scope            # load scope from bounties CLI (safe)
  hunt.py <handle> enum             # subfinder — passive subdomain enum (safe)
  hunt.py <handle> live             # httpx — active: HTTP probes to target
  hunt.py <handle> crawl            # katana — active: crawl live hosts
  hunt.py <handle> scan             # nuclei — active: vuln templates
  hunt.py <handle> status           # summarize what's been done + findings
  hunt.py <handle> clear            # wipe this target's workdir

Environment:
  HUNT_DIR — override workdir root (default ~/.cache/hunt)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

BOUNTIES_CLI = Path(__file__).parent / "bounties.py"
TRACKER_CLI = Path(__file__).parent / "tracker.py"
HUNT_ROOT = Path(os.environ.get("HUNT_DIR", Path.home() / ".cache" / "hunt"))
ACTIVE_PHASES = {"live", "crawl", "js_mine", "param_mine", "scan"}


def tracker_advance(handle: str, phase: str, output: str | None) -> None:
    """Best-effort tracker update; silent if the program isn't tracked yet."""
    cmd = [str(TRACKER_CLI), "advance", handle, phase]
    if output:
        cmd += ["--output", output]
    subprocess.run(cmd, capture_output=True, text=True, check=False)


# ---------- workspace ----------

def workdir(handle: str) -> Path:
    d = HUNT_ROOT / handle
    d.mkdir(parents=True, exist_ok=True)
    return d


def log(handle: str, msg: str) -> None:
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {msg}"
    print(line)
    (workdir(handle) / "journal.log").open("a").write(line + "\n")


# ---------- scope ----------

def load_scope(handle: str, platform: str | None = None) -> dict:
    """Fetch normalized scope via the bounties CLI."""
    cmd = [str(BOUNTIES_CLI), "show", handle, "--json"]
    if platform:
        cmd += ["--platform", platform]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        sys.exit(f"bounties CLI failed: {r.stderr.strip() or r.stdout.strip()}")
    return json.loads(r.stdout)


def scope_targets(scope: dict) -> dict[str, list[str]]:
    """Split scope in-scope targets into url/wildcard/other buckets."""
    urls: list[str] = []
    wildcards: list[str] = []
    other: list[tuple[str, str]] = []
    for t in scope["in_scope"]:
        kind = (t.get("type") or "").lower()
        tgt = (t.get("target") or "").strip()
        if not tgt:
            continue
        if kind == "wildcard" or tgt.startswith("*."):
            wildcards.append(tgt.lstrip("*.").lstrip("."))
        elif kind in {"url", "website", "api", "web-application"} or tgt.startswith(("http://", "https://")):
            urls.append(tgt)
        else:
            other.append((kind or "?", tgt))
    return {"urls": urls, "wildcards": wildcards, "other": [f"{k}: {v}" for k, v in other]}


# ---------- phases ----------

def phase_scope(handle: str, platform: str | None) -> None:
    scope = load_scope(handle, platform)
    wd = workdir(handle)
    (wd / "scope.json").write_text(json.dumps(scope, indent=2))
    buckets = scope_targets(scope)
    (wd / "targets_urls.txt").write_text("\n".join(buckets["urls"]) + "\n" if buckets["urls"] else "")
    (wd / "targets_wildcards.txt").write_text("\n".join(buckets["wildcards"]) + "\n" if buckets["wildcards"] else "")
    (wd / "targets_other.txt").write_text("\n".join(buckets["other"]) + "\n" if buckets["other"] else "")

    log(handle, f"scope loaded: {scope['platform']}/{scope['handle']} — {scope['name']}")
    log(handle, f"  bounty: min={scope.get('min_bounty')} max={scope.get('max_bounty')} offers={scope['offers_bounty']}")
    log(handle, f"  in-scope: {len(buckets['urls'])} urls, {len(buckets['wildcards'])} wildcards, {len(buckets['other'])} other")
    log(handle, f"  out-of-scope: {len(scope['out_of_scope'])}")
    print(f"\nworkdir: {wd}")
    tracker_advance(handle, "scope", str(wd / "scope.json"))


def phase_enum(handle: str) -> None:
    """Passive subdomain enum over wildcard scope (subfinder uses third-party DNS sources)."""
    wd = workdir(handle)
    wildcards_file = wd / "targets_wildcards.txt"
    if not wildcards_file.exists() or not wildcards_file.read_text().strip():
        sys.exit("no wildcards in scope — run `hunt.py <handle> scope` first, or this program has no wildcard scope")
    out = wd / "subs.txt"
    cmd = ["subfinder", "-dL", str(wildcards_file), "-silent", "-o", str(out)]
    log(handle, f"running: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=False, text=True, check=False)
    if r.returncode != 0:
        log(handle, f"subfinder exit code {r.returncode}")
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"enum complete: {count} subdomains → {out}")
    tracker_advance(handle, "enum", str(out))


def phase_live(handle: str, concurrency: int, rate: int) -> None:
    """httpx probe — ACTIVE: sends HTTP requests to each target."""
    wd = workdir(handle)
    subs = wd / "subs.txt"
    urls = wd / "targets_urls.txt"
    combined = wd / "candidates.txt"
    lines: set[str] = set()
    if subs.exists():
        lines.update(l.strip() for l in subs.read_text().splitlines() if l.strip())
    if urls.exists():
        lines.update(l.strip() for l in urls.read_text().splitlines() if l.strip())
    if not lines:
        sys.exit("no candidates to probe — run `scope` and `enum` first")
    combined.write_text("\n".join(sorted(lines)) + "\n")

    out = wd / "live.jsonl"
    cmd = [
        "httpx",
        "-l", str(combined),
        "-silent",
        "-title", "-status-code", "-tech-detect", "-server", "-ip",
        "-json",
        "-threads", str(concurrency),
        "-rl", str(rate),
        "-o", str(out),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"live probe complete: {count} responsive hosts → {out}")
    tracker_advance(handle, "live", str(out))


def phase_crawl(handle: str, concurrency: int, rate: int) -> None:
    """katana crawl — ACTIVE: follows links on every live host."""
    wd = workdir(handle)
    live = wd / "live.jsonl"
    if not live.exists():
        sys.exit("no live.jsonl — run `live` first")
    live_urls = wd / "live_urls.txt"
    with live.open() as fh, live_urls.open("w") as out:
        for line in fh:
            try:
                rec = json.loads(line)
                url = rec.get("url") or rec.get("input")
                if url:
                    out.write(url + "\n")
            except json.JSONDecodeError:
                continue
    out_file = wd / "katana.jsonl"
    cmd = [
        "katana",
        "-list", str(live_urls),
        "-silent",
        "-jsonl",
        "-d", "2",
        "-c", str(concurrency),
        "-rl", str(rate),
        "-o", str(out_file),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out_file.open()) if out_file.exists() else 0
    log(handle, f"crawl complete: {count} URLs → {out_file}")
    tracker_advance(handle, "crawl", str(out_file))


def phase_code_recon(handle: str, gh_org: str | None) -> None:
    """GitHub code recon — passive relative to the target. Needs GITHUB_TOKEN.

    Two inputs matter:
      - `gh_org` (optional): the target's GitHub organization handle, if known.
        Enables trufflehog org-wide secret scanning. If omitted, only
        github-subdomains runs (queries GitHub code search for the scope's
        root domains).
    """
    wd = workdir(handle)
    code_dir = wd / "code_recon"
    code_dir.mkdir(exist_ok=True)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        # Try gh CLI's cached token as a fallback.
        try:
            r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=False)
            if r.returncode == 0 and r.stdout.strip():
                token = r.stdout.strip()
                os.environ["GITHUB_TOKEN"] = token
        except FileNotFoundError:
            pass
    if not token:
        sys.exit("GITHUB_TOKEN not set and `gh auth token` unavailable — GitHub API is rate-limited to 60 req/hr unauthenticated; set a token before running code_recon")

    # 1. github-subdomains on each wildcard root
    wildcards = wd / "targets_wildcards.txt"
    if wildcards.exists() and wildcards.read_text().strip():
        all_found: set[str] = set()
        for domain in [l.strip() for l in wildcards.read_text().splitlines() if l.strip()]:
            log(handle, f"github-subdomains -d {domain}")
            out_file = code_dir / f"gh_subs_{domain.replace('/', '_')}.txt"
            r = subprocess.run(
                ["github-subdomains", "-d", domain, "-o", str(out_file), "-t", token],
                capture_output=True, text=True, check=False, timeout=300,
            )
            if out_file.exists():
                for line in out_file.read_text().splitlines():
                    line = line.strip()
                    if line:
                        all_found.add(line)
        combined = code_dir / "gh_subs_all.txt"
        combined.write_text("\n".join(sorted(all_found)) + "\n")
        log(handle, f"  github-subdomains found {len(all_found)} unique hosts → {combined}")
    else:
        log(handle, "  no wildcards in scope — skipping github-subdomains")

    # 2. trufflehog org-wide secret scan — optional, only if gh_org provided
    if gh_org:
        out_jsonl = code_dir / f"trufflehog_{gh_org}.jsonl"
        cmd = ["trufflehog", "github", f"--org={gh_org}", "--json", "--only-verified", "--no-update"]
        log(handle, f"running: {' '.join(cmd)} (org scan — may take several minutes)")
        with out_jsonl.open("w") as out:
            subprocess.run(cmd, stdout=out, stderr=subprocess.DEVNULL, check=False, timeout=1800, env={**os.environ, "GITHUB_TOKEN": token})
        count = sum(1 for _ in out_jsonl.open()) if out_jsonl.exists() else 0
        log(handle, f"  trufflehog found {count} verified secrets in github.com/{gh_org} → {out_jsonl}")
    else:
        log(handle, "  no --gh-org specified — skipping trufflehog org scan")
        log(handle, "  to enable: rerun with --gh-org <organization> once you've identified the target's GitHub org")

    tracker_advance(handle, "code_recon", str(code_dir))


def phase_archive(handle: str, concurrency: int) -> None:
    """gau — passive: queries Wayback/CommonCrawl/OTX/URLScan for historical URLs.
    Strictly a read against third-party archives, no traffic to the target.
    """
    wd = workdir(handle)
    wildcards = wd / "targets_wildcards.txt"
    urls_file = wd / "targets_urls.txt"

    # gau accepts root domains on stdin. Feed both wildcards and host-extracted
    # URL targets so archives are queried for every root in scope.
    domains: set[str] = set()
    if wildcards.exists():
        domains.update(l.strip() for l in wildcards.read_text().splitlines() if l.strip())
    if urls_file.exists():
        for line in urls_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            from urllib.parse import urlparse
            host = urlparse(line).netloc or line
            if host:
                domains.add(host)
    if not domains:
        sys.exit("no domains to archive-mine — run `scope` first")

    feed = wd / "archive_input.txt"
    feed.write_text("\n".join(sorted(domains)) + "\n")
    out = wd / "archive_urls.txt"

    cmd = ["gau", "--subs", "--threads", str(concurrency), "--o", str(out)]
    log(handle, f"running: cat {feed} | {' '.join(cmd)}")
    with feed.open() as fh:
        subprocess.run(cmd, stdin=fh, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"archive complete: {count} historical URLs → {out}")
    tracker_advance(handle, "archive", str(out))


# Regex-based JS miner. AST-based extraction via jsluice needs a C toolchain
# we don't have; these patterns cover ~80% of jsluice's value for bounty work
# (hardcoded secrets in unminified customer JS + endpoint strings).
_JS_SECRET_PATTERNS = {
    "aws_access_key":     r"AKIA[0-9A-Z]{16}",
    "google_api_key":     r"AIza[0-9A-Za-z\-_]{35}",
    "github_token":       r"ghp_[0-9a-zA-Z]{36}",
    "github_oauth":       r"gho_[0-9a-zA-Z]{36}",
    "stripe_live_sk":     r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_live_pk":     r"pk_live_[0-9a-zA-Z]{24,}",
    "slack_token":        r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "jwt":                r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*",
    "firebase_url":       r"https://[\w\-]+\.firebaseio\.com",
    "firebase_apikey":    r"firebaseConfig[^}]*apiKey\s*:\s*[\"'][^\"']+[\"']",
    "private_key_header": r"-----BEGIN (?:RSA |EC |DSA |ED25519 )?PRIVATE KEY-----",
    "mailgun_key":        r"key-[0-9a-f]{32}",
    "twilio_sid":         r"AC[0-9a-fA-F]{32}",
}
_JS_URL_RE  = re.compile(r'https?://[^\s\'"<>`]+', re.I)
_JS_PATH_RE = re.compile(r'[\'"](/(?:api|v\d+|internal|admin|debug|graphql|oauth|auth|rest)/[^\'"<>\s`]*)[\'"]', re.I)


def phase_js_mine(handle: str, concurrency: int) -> None:
    """Extract JS URLs from live corpus, fetch each, regex-scan for secrets + API paths.
    ACTIVE: GETs each JS file from the target.
    """
    wd = workdir(handle)
    live = wd / "live_urls.txt"
    if not live.exists():
        # Derive from live.jsonl if it exists
        live_jsonl = wd / "live.jsonl"
        if live_jsonl.exists():
            with live_jsonl.open() as fh, live.open("w") as out:
                for line in fh:
                    try:
                        url = (json.loads(line).get("url") or "").strip()
                        if url:
                            out.write(url + "\n")
                    except json.JSONDecodeError:
                        continue
        else:
            sys.exit("no live hosts — run `live` first")

    js_urls_file = wd / "js_urls.txt"
    log(handle, f"running (ACTIVE): subjs < {live}")
    with live.open() as fh:
        r = subprocess.run(["subjs"], stdin=fh, capture_output=True, text=True, check=False)
    js_urls_file.write_text(r.stdout)
    js_urls = [u.strip() for u in r.stdout.splitlines() if u.strip()]
    log(handle, f"  {len(js_urls)} JS URLs discovered")

    if not js_urls:
        tracker_advance(handle, "js_mine", str(js_urls_file))
        return

    # Fetch each JS file and regex-scan. Cap at the first 200 to keep a single
    # run bounded; if more exist, log a warning.
    import urllib.request
    out_file = wd / "js_findings.jsonl"
    capped = js_urls[:200]
    if len(js_urls) > 200:
        log(handle, f"  capping JS fetch at 200 (have {len(js_urls)})")

    findings = 0
    with out_file.open("w") as out:
        for i, u in enumerate(capped, 1):
            try:
                req = urllib.request.Request(u, headers={"User-Agent": "hunter-js-miner"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
            except Exception as e:
                continue

            for kind, pat in _JS_SECRET_PATTERNS.items():
                for m in re.finditer(pat, body):
                    out.write(json.dumps({
                        "type": "secret",
                        "kind": kind,
                        "js_url": u,
                        "match": m.group(0)[:300],
                    }) + "\n")
                    findings += 1
            for m in _JS_URL_RE.finditer(body):
                out.write(json.dumps({"type": "absolute_url", "js_url": u, "url": m.group(0)[:500]}) + "\n")
            for m in _JS_PATH_RE.finditer(body):
                out.write(json.dumps({"type": "api_path", "js_url": u, "path": m.group(1)[:500]}) + "\n")

    log(handle, f"js_mine complete: {findings} secret-like hits in {len(capped)} JS files → {out_file}")
    tracker_advance(handle, "js_mine", str(out_file))


def phase_param_mine(handle: str, concurrency: int, rate: int, sample: int) -> None:
    """Arjun param discovery on a sampled set of live URLs. ACTIVE: diffing probes."""
    wd = workdir(handle)
    live_urls = wd / "live_urls.txt"
    if not live_urls.exists():
        sys.exit("no live_urls.txt — run `live` first")

    # Dedup by host+path so we don't repeatedly mine the same endpoint.
    from urllib.parse import urlparse, urlunparse
    seen: set[str] = set()
    candidates: list[str] = []
    for u in live_urls.read_text().splitlines():
        u = u.strip()
        if not u:
            continue
        p = urlparse(u)
        key = (p.netloc, p.path)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(u)

    if sample and len(candidates) > sample:
        log(handle, f"sampling {sample} of {len(candidates)} unique endpoints for param mining")
        candidates = candidates[:sample]

    feed = wd / "param_mine_input.txt"
    feed.write_text("\n".join(candidates) + "\n")
    out = wd / "hidden_params.json"
    cmd = ["arjun", "-i", str(feed), "-oJ", str(out), "-t", str(concurrency), "--rate-limit", str(rate)]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    if out.exists():
        try:
            data = json.loads(out.read_text())
            total = sum(len(v.get("params", [])) for v in data.values()) if isinstance(data, dict) else 0
            log(handle, f"param_mine complete: {total} hidden parameters across {len(candidates)} endpoints → {out}")
        except (json.JSONDecodeError, AttributeError):
            log(handle, f"param_mine complete (output at {out}, format unexpected)")
    tracker_advance(handle, "param_mine", str(out))


def phase_scan(handle: str, concurrency: int, rate: int, severities: str) -> None:
    """nuclei template scan — ACTIVE: sends vuln-check payloads to live hosts."""
    wd = workdir(handle)
    live = wd / "live.jsonl"
    if not live.exists():
        sys.exit("no live.jsonl — run `live` first")
    live_urls = wd / "live_urls.txt"
    if not live_urls.exists():
        with live.open() as fh, live_urls.open("w") as out:
            for line in fh:
                try:
                    url = (json.loads(line).get("url") or "").strip()
                    if url:
                        out.write(url + "\n")
                except json.JSONDecodeError:
                    pass
    out = wd / "nuclei.jsonl"
    cmd = [
        "nuclei",
        "-l", str(live_urls),
        "-silent",
        "-jsonl",
        "-severity", severities,
        "-c", str(concurrency),
        "-rl", str(rate),
        "-o", str(out),
    ]
    log(handle, f"running (ACTIVE): {' '.join(cmd)}")
    subprocess.run(cmd, capture_output=False, text=True, check=False)
    count = sum(1 for _ in out.open()) if out.exists() else 0
    log(handle, f"scan complete: {count} findings → {out}")
    tracker_advance(handle, "scan", str(out))


def phase_status(handle: str) -> None:
    wd = workdir(handle)
    if not wd.exists():
        sys.exit(f"no workdir for {handle} — nothing run yet")
    files = {
        "scope.json":        "scope",
        "subs.txt":          "enum (subdomains)",
        "archive_urls.txt":  "archive (gau)",
        "live.jsonl":        "live probes",
        "katana.jsonl":      "crawl",
        "js_findings.jsonl": "js_mine",
        "hidden_params.json":"param_mine",
        "nuclei.jsonl":      "scan findings",
    }
    print(f"\nworkdir: {wd}\n")
    for name, label in files.items():
        p = wd / name
        if not p.exists():
            print(f"  [ ] {label:20} —")
            continue
        if name.endswith(".jsonl") or name.endswith(".txt"):
            count = sum(1 for _ in p.open())
            print(f"  [x] {label:20} {count:>6} entries    {p.stat().st_size} B")
        else:
            print(f"  [x] {label:20}              {p.stat().st_size} B")
    print()
    journal = wd / "journal.log"
    if journal.exists():
        print("recent log entries:")
        for line in journal.read_text().splitlines()[-8:]:
            print(f"  {line}")


def phase_clear(handle: str) -> None:
    wd = workdir(handle)
    if not wd.exists():
        print(f"no workdir for {handle}")
        return
    import shutil
    shutil.rmtree(wd)
    print(f"wiped {wd}")


# ---------- CLI ----------

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="hunt",
        description="Per-target recon harness — each phase is an explicit step.",
    )
    ap.add_argument("handle", help="program handle (e.g. shopify, kruidvat)")
    ap.add_argument("phase", choices=["scope", "enum", "archive", "live", "crawl", "js_mine", "param_mine", "scan", "code_recon", "status", "clear"])
    ap.add_argument("--platform", choices=("hackerone", "bugcrowd", "intigriti", "yeswehack"),
                    help="disambiguate if handle collides")
    ap.add_argument("-c", "--concurrency", type=int, default=25, help="worker threads (active phases)")
    ap.add_argument("--rl", type=int, default=50, help="requests per second rate limit (active phases)")
    ap.add_argument("--severity", default="low,medium,high,critical",
                    help="nuclei severities, comma-separated")
    ap.add_argument("--sample", type=int, default=50, help="param-mine: cap number of unique endpoints probed")
    ap.add_argument("--gh-org", dest="gh_org", help="code_recon: target's GitHub organization handle (enables trufflehog org scan)")
    args = ap.parse_args()

    if args.phase in ACTIVE_PHASES:
        print(f"[!] {args.phase.upper()} is an ACTIVE phase — sends traffic to the target.")
        print("    Confirm the target's program policy allows automated scanning before proceeding.\n")

    phases = {
        "scope":      lambda: phase_scope(args.handle, args.platform),
        "enum":       lambda: phase_enum(args.handle),
        "archive":    lambda: phase_archive(args.handle, args.concurrency),
        "code_recon": lambda: phase_code_recon(args.handle, args.gh_org),
        "live":       lambda: phase_live(args.handle, args.concurrency, args.rl),
        "crawl":      lambda: phase_crawl(args.handle, args.concurrency, args.rl),
        "js_mine":    lambda: phase_js_mine(args.handle, args.concurrency),
        "param_mine": lambda: phase_param_mine(args.handle, args.concurrency, args.rl, args.sample),
        "scan":       lambda: phase_scan(args.handle, args.concurrency, args.rl, args.severity),
        "status":     lambda: phase_status(args.handle),
        "clear":      lambda: phase_clear(args.handle),
    }
    phases[args.phase]()


if __name__ == "__main__":
    main()
