# ADR 0007: Satellite Insert Failures Are Partial, Not Fatal

- Status: Accepted
- Date: 2026-09-14

## Context

A successful `url_status` row can still fail to persist some child tables (DNS, cookies, GeoIP, and so on). Historically those SQL errors were `log::warn` only: the fact row committed, and operators could not tell “not observed” from “insert failed.” Scan-time DNS/TLS misses already land in `url_partial_failures`. Storage-layer misses did not.

Enrichment children were also deleted inside the `url_status` transaction and rewritten after commit, so a crash or overlapping UPSERT could blank GeoIP/WHOIS/secrets while the fact row looked successful.

## Decision

- In-transaction (core) satellite SQL failures do **not** roll back `url_status`. Partial child data is better than losing the observation.
- Those failures are persisted as `url_partial_failures` rows with `error_type` `Satellite insert error` and a message that names the child table.
- Enrichment satellites are replaced in a **second writer transaction** (DELETE + INSERT). Core UPSERT does not delete enrichment tables, so concurrent readers keep the previous enrichment until the new enrichment transaction commits.
- Scan-time partials and satellite/enrichment insert failures are written in that enrichment transaction after the DELETE, so they are not wiped by cleanup.

This extends [ADR 0002](0002-enrichment-failure-policy.md) (best-effort enrichments) to the storage layer without making satellite SQL fatal.

## Consequences

Positive:

- Query `url_partial_failures` where `error_type = 'Satellite insert error'` to distinguish insert gaps from “not observed.”
- Rescans no longer expose an empty enrichment window after the fact row commits.

Trade-offs:

- A successful URL can still have incomplete children; consumers must treat satellites as optionally present.
- If the enrichment transaction itself fails to begin or commit, prior enrichment is kept and satellite insert failures are only in logs for that attempt.

## Related Code

- `src/storage/insert/url/core_satellites.rs` (`URL_STATUS_CORE_SATELLITE_TABLES`)
- `src/storage/insert/url/upsert.rs` (core UPSERT + in-txn satellite writes)
- `src/storage/insert/record.rs` (`insert_enrichment_data`)
- `src/error_handling/types.rs` (`ErrorType::SatelliteInsertError`)
