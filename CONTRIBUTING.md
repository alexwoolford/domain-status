# Contributing to `domain_status`

`just` is the canonical developer interface for this repository. Start there unless you are debugging a specific raw Cargo invocation.

## Quick Bootstrap

```bash
git clone https://github.com/alexwoolford/domain_status.git
cd domain_status
cargo install just
just --list
just check
```

If you use pre-commit hooks:

```bash
pip install pre-commit
just install-hooks
```

For the full environment bootstrap, helper CLI list, cache/network behavior, and writable-directory assumptions, see `docs/DEVELOPER_BOOTSTRAP.md`.

## Required Tooling

- Rust `1.85+`
- `just`

## Commonly Expected Optional Tooling

These are not required for every code change, but parts of the docs, local workflows, or CI assume they are available:

- `pre-commit`
- `cargo-audit`
- `cargo-tarpaulin`
- `cargo-outdated`
- `sqlite3`
- `jq`
- `curl`
- `wget` or equivalent downloader

## Main Workflows

Use `just` recipes for the routine path:

```bash
just check      # fmt + lint + docs + test
just docs-check # doctests + rustdoc warnings
just ci         # fmt-check + lint + docs-check + test + audit + deny
just test       # deterministic unit/integration suite
just test-e2e   # ignored tests, requires network
just coverage   # tarpaulin coverage report
just audit      # cargo audit
just outdated   # dependency drift check
```

## Before Opening a PR

Run the relevant local gates for your change. Before submitting, run format, lint, docs, and tests so CI passes:

- **Recommended:** `just check` (runs `cargo fmt`, clippy, docs-check, and tests).
- **Or manually:** `cargo fmt`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked`, and `cargo test --all-features --all-targets --locked`.

In most cases:

```bash
just check
```

If you changed CI-sensitive behavior, security-sensitive code, or docs/build logic, prefer:

```bash
just ci
```

If you changed documentation or Rustdoc, also run:

```bash
just docs-check
```

## Adding a Captured Field

When extending what a scan persists (or exports), use this checklist so parallel lists do not drift:

### New `url_status` column

1. Add a migration under `migrations/` and update [`DATABASE.md`](DATABASE.md).
2. Add the field to [`UrlRecord`](src/storage/models.rs) (and `UrlRecord::test_default`).
3. Add one entry to [`URL_STATUS_COLUMN_DEFS`](src/storage/insert/url/mod.rs) (name + bind extractor). Do **not** hand-edit a separate bind chain — SQL and binds are derived from this table.
4. Populate the field in the fetch/build path (`build_url_record` / capture structs).
5. Decide export:
   - Flat export (CSV/Parquet/JSONL): update `MainRowData` / `extract_main_row_data`, export query, and format serializers (`CSV_COLUMN_DEFS`, Parquet schema, JSONL). Add to `URL_STATUS_REQUIRED_IN_FLAT_EXPORT` in [`field_inventory.rs`](src/export/field_inventory.rs) if consumers must see it.
   - DB-only: add the column name to `URL_STATUS_DB_ONLY` in that inventory module so omission stays intentional.

### New satellite / enrichment table

1. Migration + `DATABASE.md`.
2. Insert helper under `src/storage/insert/url/satellite/` (core) or `src/storage/insert/enrichment/` (enrichment).
3. Wire into `BatchRecord` / `build_batch_record`. Core satellites also need `UrlRecordInsertParams`, `from_batch`, and `with_empty_satellites`. Enrichment goes through `insert_enrichment_data` instead.
4. Add the table name to [`URL_STATUS_SATELLITE_TABLES`](src/storage/insert/url/mod.rs) so UPSERT cleanup clears stale rows (production and upsert-clear tests share this list).
5. Export only if needed (same decision as above; satellite-only tables often stay DB-queryable — document in `SATELLITE_DB_ONLY` when intentional).

### New CLI / config flag

Update clap (`cli/`), `Config` + `Default`, file/env merge arms, and `SCAN_CONFIG_ARG_IDS` together — missing one step silently ignores the flag for file/env.

## Testing Expectations

Testing guidance lives in `TESTING.md`. The short version:

- default tests must be deterministic and local-only
- live-network tests stay `#[ignore]`
- if a live/manual repro finds a bug, add a deterministic regression test before or alongside the fix

## Commit Messages

Use concise, descriptive messages. Conventional-commit style is welcome:

- `feat`
- `fix`
- `docs`
- `refactor`
- `test`
- `chore`

## Getting Help

- Open an Issue for bugs or feature requests
- Open a Discussion for questions or design conversation
