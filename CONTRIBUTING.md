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
just check      # fmt + lint + test
just docs-check # doctests + rustdoc warnings
just ci         # fmt-check + lint + test + audit
just test       # deterministic unit/integration suite
just test-e2e   # ignored tests, requires network
just coverage   # tarpaulin coverage report
just audit      # cargo audit
just outdated   # dependency drift check
```

## Before Opening a PR

Run the relevant local gates for your change. Before submitting, run format, lint, and tests so CI passes:

- **Recommended:** `just check` (runs `cargo fmt`, `cargo clippy`, and `cargo test`).
- **Or manually:** `cargo fmt`, `cargo clippy --all-targets --all-features --locked -- -D warnings`, and `cargo test --all-features --all-targets --locked`.

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
