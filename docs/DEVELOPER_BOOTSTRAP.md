# Developer Bootstrap

This is the single source of truth for setting up a contributor environment for `domain_status`.

## 1. Required Tools

Install these first:

- Rust `1.85+`
- `just`

Recommended installs:

```bash
rustup update stable
cargo install just
```

## 2. Optional but Commonly Needed Tools

These are used by CI-equivalent recipes, docs, or local investigation workflows:

- `pre-commit`
- `cargo-audit`
- `cargo-tarpaulin`
- `cargo-outdated`
- `sqlite3`
- `jq`
- `curl`
- `wget` or another downloader

Suggested installs:

```bash
cargo install cargo-audit --locked
cargo install cargo-tarpaulin --locked
cargo install cargo-outdated --locked
pip install pre-commit
```

On some systems you may prefer package-manager installs for `sqlite3`, `jq`, `curl`, and `wget`.

## 3. First Commands After Clone

```bash
git clone https://github.com/alexwoolford/domain_status.git
cd domain_status
just --list
just check
```

If you want local pre-commit enforcement:

```bash
just install-hooks
```

## 4. Canonical Task Runner

Use `just` as the primary interface:

| Command | Purpose |
|--------|---------|
| `just check` | Local fast path: format, lint, tests |
| `just docs-check` | Doctests plus rustdoc warning gate |
| `just ci` | Main local CI equivalent |
| `just test` | Deterministic unit and integration tests |
| `just test-e2e` | Ignored tests that require real network access |
| `just coverage` | Tarpaulin coverage run |
| `just audit` | Dependency vulnerability audit |
| `just outdated` | Dependency drift check |

Raw Cargo commands are still useful for debugging, but `just` should stay the documented happy path.

## 5. Network and Cache Behavior

Cold-start runs may perform outbound network requests before the first URL is fully processed.

### Fingerprint rulesets

By default the scanner fetches and merges upstream fingerprint rules from:

- `enthec/webappanalyzer`
- `HTTPArchive/wappalyzer`

The merged ruleset is cached in:

- `.fingerprints_cache/`

Tips:

- first run may hit GitHub-hosted content
- `GITHUB_TOKEN` is optional but helps avoid GitHub API rate limits for metadata lookups

### User-Agent refresh

If you keep the built-in default User-Agent, the scanner may fetch the latest Chrome version and cache it in:

- `.user_agent_cache/version.json`

This cache lasts 30 days.

### GeoIP

GeoIP is best-effort and only active when configured.

- automatic download path requires `MAXMIND_LICENSE_KEY`
- cache location: `.geoip_cache/`
- cold-cache GeoIP initialization may download MaxMind data
- failures do not abort the scan; the scanner continues without GeoIP

### WHOIS

WHOIS/RDAP is disabled unless `--enable-whois` is set.

- cache location: `.whois_cache/`
- cache TTL: 7 days
- lookups are best-effort and can legitimately return `None`

## 6. Writable-Directory Assumptions

The process expects write access for:

- `./domain_status.db` unless `--db-path` is overridden
- `./domain_status.log` during `scan`
- `.fingerprints_cache/`
- `.geoip_cache/`
- `.whois_cache/`
- `.user_agent_cache/`

If you run inside a sandboxed or read-only environment, set alternate paths or pre-create the writable directories you need.

## 7. Temp Directory Assumptions

In a source checkout, migrations are usually read directly from `./migrations`.

When the source migrations directory is not present, embedded migrations are extracted to a temporary directory before being run. That means:

- the environment needs a writable temp directory
- tests or packaging flows that emulate distributed binaries should preserve this assumption

## 8. Local Databases and Sample Validation

Common local inspection tools:

```bash
sqlite3 domain_status.db ".tables"
sqlite3 domain_status.db "SELECT run_id, total_urls, successful_urls, failed_urls FROM runs ORDER BY start_time_ms DESC LIMIT 5;"
domain_status export --format jsonl --output - 2>/dev/null | jq '.final_domain'
```

Sample validation flow:

```bash
# domains.txt: one URL or domain per line
./target/release/domain_status scan domains.txt --db-path validation_scan.db
sqlite3 validation_scan.db "SELECT COUNT(*) FROM url_status;"
./target/release/domain_status export --db-path validation_scan.db --format csv --output /tmp/validation_export.csv
```

## 9. Docs and Rustdoc Validation

When changing documentation, README examples, or public API docs, run:

```bash
cargo test --doc
```

If CI or local recipes add a dedicated docs gate, run that too.

## 10. Troubleshooting

### `just` not found

Install it with:

```bash
cargo install just
```

### Scan works locally but CI fails

Check whether your local run depended on:

- warm caches
- network access
- local tools not documented in `just` or CI
- writable working-directory state

### Fingerprint initialization is slow or rate-limited

- retry with `GITHUB_TOKEN` set
- or point `--fingerprints` at a local ruleset path for deterministic local work
