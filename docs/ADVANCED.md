# Advanced usage

This page covers optional enrichments, caches, and operational tuning. For the happy path, see the [README](../README.md).

## Shared cache root

Fingerprints, GeoIP, WHOIS, and User-Agent refresh data share one root:

1. `--cache-dir` / `Config.cache_dir`
2. `DOMAIN_STATUS_CACHE_DIR`
3. Platform XDG cache: `~/.cache/domain_status/` (Linux/macOS) or equivalent
4. Fallback: `./domain_status/…` under the process cwd when no cache home exists

Subdirectories:

| Subdir | Contents |
|--------|----------|
| `fingerprints/` | Merged ruleset cache (7-day TTL) |
| `geoip/` | GeoLite2 City/ASN MMDB + metadata |
| `whois/` | Per-domain WHOIS/RDAP JSON (7-day TTL) |
| `user_agent/` | Chrome version cache (30-day TTL) |

**Not caches:** `--db-path` (SQLite) and `--log-file` remain explicit outputs (cwd by default).

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

## External script secret scanning

`--scan-external-scripts` fetches first-party `<script src>` URLs only (same eTLD+1; CDN denylist). Off by default; expands latency and fetch surface.

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
