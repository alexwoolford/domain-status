# ADR 0002: Enrichment Failure Policy

- Status: Accepted
- Date: 2026-03-01

## Context

The scanner combines core URL-processing work with several enrichments and support services:

- fingerprint initialization
- GeoIP
- WHOIS/RDAP
- User-Agent refresh
- status telemetry

Not all of these should have identical failure semantics. Some are required for the scan to make sense at all; others should degrade gracefully so a large batch can still complete.

The main orchestration logic lives in `src/run/init.rs`.

## Decision

We explicitly split dependencies into two categories.

### Mandatory

These failures abort startup or the current operation:

- configuration validation
- database initialization and migrations
- HTTP client and resolver initialization
- fingerprint ruleset initialization
- inserting initial run metadata

### Best-effort / degradable

These failures do not abort a scan:

- GeoIP initialization or refresh
- WHOIS lookups
- Chrome-version refresh for the default User-Agent
- ongoing status/metrics reporting after successful startup

The scanner records or logs degraded behavior rather than pretending the enrichment was successful.

## Consequences

Positive:

- core scans still complete when optional enrichments are unavailable
- production behavior is more resilient to third-party outages
- operational teams can distinguish "scan failed" from "scan completed with reduced enrichment"

Trade-offs:

- result completeness can vary between runs
- downstream consumers must treat some enrichment fields as legitimately absent
- observability becomes more important because absence can be intentional degradation rather than a parsing bug

## Operational Notes

- GeoIP failures log a warning and scanning continues without GeoIP enrichment
- WHOIS is opt-in and returns `None` on timeout or backend failure
- runtime metrics and status endpoints are the preferred place to surface degradation signals

## Related Code

- `src/run/init.rs`
- `src/geoip/init/mod.rs`
- `src/whois/mod.rs`
- `src/user_agent.rs`
- `src/status_server/handlers/status.rs`
- `src/status_server/handlers/metrics.rs`
