# Advanced usage

This page covers optional enrichments, caches, and operational tuning. For the happy path, see the [README](../README.md).

## Shared cache root

Fingerprints, GeoIP, WHOIS, and User-Agent refresh data share one root:

1. `--cache-dir` / `Config.cache_dir`
2. `DOMAIN_STATUS_CACHE_DIR`
3. Platform cache dir (`dirs::cache_dir`) + `domain_status/`:
   - Linux: `~/.cache/domain_status` (or `$XDG_CACHE_HOME/domain_status`)
   - macOS: `~/Library/Caches/domain_status`
   - Windows: `%LOCALAPPDATA%\domain_status`
4. Fallback: `./domain_status/…` under the process cwd when no cache home exists

Subdirectories:

| Subdir | Contents |
|--------|----------|
| `fingerprints/` | Merged ruleset cache (7-day TTL); superseded hash dirs pruned after a successful refresh |
| `geoip/` | GeoLite2 City/ASN MMDB + metadata (7-day TTL; orphaned `.*.tmp` cleaned on init) |
| `whois/` | Per-domain WHOIS/RDAP JSON (7-day TTL). One client per scan; rate-limited and not-found responses are not cached. |
| `user_agent/` | Chrome version cache (30-day TTL) |

**Not caches:** `--db-path` (SQLite) and `--log-file` remain explicit outputs (cwd by default).

### Recommended production layout

Keep regenerable caches under the platform cache root (or `--cache-dir`). Point durable scan outputs somewhere deliberate, for example:

```bash
domain-status scan urls.txt \
  --db-path /var/lib/domain_status/scan.db \
  --log-file /var/log/domain_status/scan.log \
  --cache-dir /var/cache/domain_status
```

Defaults leave DB/log in the working directory so interactive runs keep results next to the command.

## Fingerprints

- Default: merge Enthec + HTTPArchive technology directories from GitHub, then apply the first-party overlay in `assets/fingerprints/overlay.json` (adds Payload; tightens Amazon S3 to hosting headers).
- `GITHUB_TOKEN` is optional rate-limit headroom (60 → 5000 GitHub API requests/hour). It is **not** required for the full catalog; a cold start lists two directories and two commit SHAs.
- Without GitHub: `--fingerprints /path/to/rules` (file or directory) for CI, restricted egress, or deterministic runs. This only skips ruleset download — scanning target URLs still needs network access to those hosts. The first-party overlay is still applied on top.
- If all remotes fail, or only one of the two default sources succeeds, or the merged catalog has fewer than 1000 technologies: the scan **aborts**. Pass `--allow-degraded-fingerprints` to continue on the bundled minimal ruleset (`vendored:assets/fingerprints`) plus overlay. A rejected `GITHUB_TOKEN` (401) is retried unauthenticated so a stale token cannot wipe both sources.
- `url_technologies` is the HTTP serving stack. Prefer `WHERE is_implied = 0` in summaries. Certificate authorities stay on `url_status.ssl_cert_issuer`. Match evidence is `detection_source`.
- `--scan-external-scripts` stays off by default (extra GETs / SSRF surface). Turn it on for SPA-heavy jobs so first-party `scripts` patterns can match.

## GeoIP

- Disabled unless `MAXMIND_LICENSE_KEY` is set (auto-download) **or** `--geoip <path|url>` points at an MMDB.
- GeoLite2 (City + ASN) *is* MaxMind’s free tier; a free MaxMind account and license key are still required to download it. There is no unlicensed “lite” fallback. Without a key or `--geoip`, GeoIP stays off and the scan continues.
- Bare `--geoip` without a value is invalid; the flag always requires a path or URL.
- Auto-download uses the shared `geoip/` cache subdirectory (7-day TTL).
- A missing `--geoip` path with `MAXMIND_LICENSE_KEY` set falls back to the same MaxMind auto-download/cache path used when `--geoip` is omitted.

## WHOIS / RDAP

- **On by default.** Disable with `--no-whois` or `enable_whois = false` in TOML.
- `--enable-whois` remains accepted for older scripts (redundant when using defaults).
- Results cached under `whois/`.

## Status server

`--status-port N` binds `127.0.0.1:N` with `/health`, `/status`, and Prometheus `/metrics`.

## External script scanning

`--scan-external-scripts` fetches first-party `<script src>` URLs only (same eTLD+1; CDN denylist). Off by default; expands latency and fetch surface. Fetched bodies are used for:

- **Secret detection** (findings tagged `external_script:<url>`)
- **Technology fingerprints** via static Wappalyzer `scripts` patterns (no JS execution)

Without the flag, fingerprints still use `scriptSrc` URL strings and inline `<script>` text from the initial HTML, plus headers/cookies/meta/NS/CNAME. Certificate issuers are stored on `url_status`, not as technologies.

## TLS certificate capture

The certificate side-channel connection resolves **all** public IP addresses for the
domain (IPv4 before IPv6) and tries a TCP connect to each on `:443` in order until
one succeeds, rather than only the first resolved address. This matters for
dual-stack (A + AAAA) hosts where IPv6 egress is broken or unreachable from the
scanning host — without the fallback, every such domain would fail certificate
capture even though its IPv4 address is perfectly reachable. Only addresses that
pass the SSRF `is_public_ip` check are attempted.

## Tuning notes

- `--timeout-seconds` is per HTTP request; overall per-URL processing budget is a separate hardcoded cap (~35s).
- `--drain-timeout-secs` aborts in-flight work after the input queue empties — raise for WHOIS-heavy small batches.
- Rate limiting: `--rate-limit-rps` is URL **admission** (one token per input URL), not per-HTTP RPS. When that cap is enabled, each host is also limited to 2 URL tokens/sec. `--rate-limit-rps 0` disables both. Lower the global cap if you see 429s.

## Profiling a slow scan

The release binary is stripped. A sample of that process will not show function names. Build the symbols profile and record a short fixture with the same flags as the long run (including `--scan-external-scripts` when that flag is on, so the profile includes script fetches):

```bash
just build-symbols
samply record --rate 999 ./target/release-with-symbols/domain-status scan fixture.txt \
  --scan-external-scripts \
  --max-concurrency 8 \
  --rate-limit-rps 3 \
  --timeout-seconds 20 \
  --db-path /tmp/profile-scan.db \
  --log-file /tmp/profile-scan.log \
  --status-port 8081
```

`samply` writes a Firefox Profiler profile (an interactive flamegraph). Without it, `sample <pid> 5 -file /tmp/domain-status.sample.txt` still shows whether time sits in `regex`, `scraper`, or `SQLite`, but only if the binary was built with `just build-symbols`.

Leave a multi-day scan running. Profile a few hundred URLs in a second process. `--status-port` exposes per-stage averages at `/status` and `/metrics` (body read, HTML parse, secret scan, fingerprint passes, external scripts, SQLite). The end-of-run timing summary prints the same averages. Body read, HTML parse, and secret scan are parts of HTML parsing. Script fetch and script analysis run in parallel with tech detection and DNS, so those percentages can overlap.

CPU-microseconds per stage on a fixed input is the electricity proxy the suite can measure. Watt-hours are machine-specific; `sudo powermetrics --samplers cpu_power -n 1` can sample package power on this Mac when a later pass needs watts. See [TESTING.md](TESTING.md) for `just bench`.

## Library embeds

See [docs.rs/domain-status](https://docs.rs/domain-status). Prefer `Config` + `run_scan` + export/summary; advanced modules may narrow in 0.x.


## Diligence profile

For portfolio infosec or light tech diligence, prefer one thorough observational run over re-scanning with extra flags later:

- WHOIS/RDAP is **on by default** (use `--no-whois` only for cheap bulk crawls)
- GeoIP: `MAXMIND_LICENSE_KEY` for auto-download, **or** `--geoip <path|url>` to an MMDB — ASN / geo
- `--scan-external-scripts` — first-party script bodies for secrets + static `scripts` tech patterns

Same-pass captures that always run (no flags): security headers (including CORS/COOP/COEP/CORP and CSP-Report-Only), parsed HSTS columns, CDN provider taxonomy, MTA-STS / TLS-RPT / BIMI TXT, `/.well-known/security.txt`, and `/robots.txt` (directives only; sitemaps are listed, not crawled).
