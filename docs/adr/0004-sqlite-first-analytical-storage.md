# ADR 0004: SQLite-First Analytical Storage

- Status: Accepted
- Date: 2026-03-01

## Context

The scanner needs a durable local store that can:

- be created automatically
- travel with the scan output as a single artifact
- support incremental writes during a batch run
- remain queryable without a separately managed service
- feed multiple export formats

`domain_status` is a CLI/batch tool first, so operating a server-side database by default would add significant deployment complexity.

## Decision

SQLite is the primary storage engine.

The database:

- defaults to `./domain_status.db`
- is created automatically if needed
- runs in WAL mode
- stores a normalized schema with one main successful-observation table plus satellites
- acts as the source for CSV, JSONL, and Parquet exports

The scanner does not require Postgres, MySQL, or another external database to be useful.

## Consequences

Positive:

- zero-service default deployment
- single-file artifact that is easy to inspect, archive, or share
- strong fit for local batch analytics and ad-hoc SQL queries
- export pipeline has one canonical source of truth

Trade-offs:

- write scalability is intentionally bounded by SQLite characteristics
- operational maintenance such as retention and VACUUM remains a local concern
- advanced multi-user serving patterns are out of scope for the default architecture

## Related Code

- `src/storage/pool.rs`
- `src/storage/migrations.rs`
- `src/storage/models.rs`
- `src/export/csv.rs`
- `src/export/jsonl.rs`
- `src/export/parquet.rs`
- `DATABASE.md`
