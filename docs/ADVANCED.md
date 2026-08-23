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
| `geoip/` | GeoLite2 City/ASN MMDB + metadata (orphaned `.*.tmp` cleaned on init) |
| `whois/` | Per-domain WHOIS/RDAP JSON (7-day TTL) |
| `user_agent/` | Chrome version cache (30-day TTL) |

**Not caches:** `--db-path` (SQLite) and `--log-file` remain explicit outputs (cwd by default).

### Recommended production layout

Keep regenerable caches under the platform cache root (or `--cache-dir`). Point durable scan outputs somewhere deliberate, for example:

```bash
domain_status scan urls.txt \
  --db-path /var/lib/domain_status/scan.db \
  --log-file /var/log/domain_status/scan.log \
  --cache-dir /var/cache/domain_status
```

Defaults leave DB/log in the working directory so interactive runs keep results next to the command.

## Fingerprints

- Default: merge Enthec + HTTPArchive technology directories from GitHub.
- `GITHUB_TOKEN` raises API rate limits for commit metadata.
- Offline: `--fingerprints /path/to/rules` (file or directory).
- If all remotes fail: bundled minimal ruleset (`vendored:assets/fingerprints`).

## GeoIP

- Disabled unless `MAXMIND_LICENSE_KEY` is set or `--geoip` points at an MMDB/URL.
- Auto-download uses the shared `geoip/` cache subdirectory.

## WHOIS / RDAP

- Off by default: `--enable-whois`.
- If TOML sets `enable_whois = true`, CLI can force off with `--no-whois`.
- Results cached under `whois/`.

## Status server

`--status-port N` binds `127.0.0.1:N` with `/health`, `/status`, and Prometheus `/metrics`.

## External script scanning

`--scan-external-scripts` fetches first-party `<script src>` URLs only (same eTLD+1; CDN denylist). Off by default; expands latency and fetch surface. Fetched bodies are used for:

- **Secret detection** (findings tagged `external_script:<url>`)
- **Technology fingerprints** via static Wappalyzer `scripts` patterns (no JS execution)

Without the flag, fingerprints still use `scriptSrc` URL strings and inline `<script>` text from the initial HTML, plus headers/cookies/meta/DNS/cert issuer.

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
- Rate limiting: lower `--rate-limit-rps` if you see 429s.

## Library embeds

See [docs.rs/domain_status](https://docs.rs/domain_status). Prefer `Config` + `run_scan` + export/summary; advanced modules may narrow in 0.x.


## Diligence profile

For portfolio infosec or light tech diligence, prefer one thorough observational run over re-scanning with extra flags later:

- `--enable-whois` — registrar / creation / expiration facts
- `--geoip` (or `MAXMIND_LICENSE_KEY`) — ASN / geo
- `--scan-external-scripts` — first-party script bodies for secrets + static `scripts` tech patterns

Same-pass captures that always run (no flags): security headers (including CORS/COOP/COEP/CORP and CSP-Report-Only), parsed HSTS columns, CDN provider taxonomy, MTA-STS / TLS-RPT / BIMI TXT, `/.well-known/security.txt`, and `/robots.txt` (directives only; sitemaps are listed, not crawled).
