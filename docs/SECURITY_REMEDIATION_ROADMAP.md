# Security Remediation Roadmap

Prioritized security findings and actions from the Security Posture Report implementation. Use this as the single place to track and schedule remediation work.

**Last reviewed:** 2026-03-01

**Related:** [ADR 0003 – TLS capture versus validation](adr/0003-tls-capture-versus-validation.md), [SECURITY.md](../SECURITY.md), [THREAT_MODEL_UNTRUSTED_INPUT.md](THREAT_MODEL_UNTRUSTED_INPUT.md), [SUPPLY_CHAIN_POSTURE.md](SUPPLY_CHAIN_POSTURE.md).

---

## Findings summary

| Area | Finding | Status |
|------|---------|--------|
| Transport trust | Page-fetch uses strict TLS; TLS capture is separate (AcceptAllVerifier only in `src/tls/`). | Documented; test added |
| Untrusted input | WHOIS, TLS, GeoIP, HTML/body have size caps and fallible parsing; one constant expect in GeoIP. | Documented in threat model |
| Secret retention | Redaction applied before DB insert and again at export; URLs/headers scrubbed before logging. | Audited; no gaps |
| Supply chain | cargo audit + cargo deny in CI; action SHA pinning; deny.toml and audit ignores documented. | Documented |

---

## Prioritized actions

### P0 (done in this pass)

- **Re-establish transport trust boundaries:** Document in code that page-fetch clients never disable TLS verification; add integration test that page-fetch rejects invalid certs (e.g. `https://self-signed.badssl.com/`).
  **Done:** [src/initialization/client.rs](src/initialization/client.rs) doc comments and `test_init_client_rejects_invalid_tls_certificate` (run with `--ignored` / in e2e job).

### P1 (ongoing / follow-up)

- **Untrusted input:** Keep all new parsing of WHOIS, TLS, GeoIP, and HTML behind `Result`/`Option`; no `unwrap`/`expect` on untrusted data. Enforce size limits before full parse. See [THREAT_MODEL_UNTRUSTED_INPUT.md](THREAT_MODEL_UNTRUSTED_INPUT.md).
- **Supply chain:** When upgrading reqwest, rustls, scraper, or parquet, re-check `.cargo/audit.toml` ignores and remove any that no longer apply. See [SUPPLY_CHAIN_POSTURE.md](SUPPLY_CHAIN_POSTURE.md).

### P2 (optional enhancements)

- **Explicit certificate trust outcomes:** Today `analyze_security()` folds expired, self-signed, and hostname mismatch into a single `InvalidCertificate` warning. Consider adding explicit fields (e.g. in the stored record or a small “certificate trust” struct) so “hostname mismatch”, “expired”, and “self-signed” are queryable/exportable.
- **GeoIP constant:** Document in code that `MAX_GEOIP_ARCHIVE_ENTRY_SIZE` must be chosen so that `+ 1` fits in u64 (for the single `.expect()` in [src/geoip/extract.rs](src/geoip/extract.rs)).

---

## Maintenance

- **Review cadence:** Revisit this roadmap and the linked docs when adding new untrusted input sources, changing TLS or client configuration, or after major dependency upgrades.
- **New findings:** Add new items to the findings table and assign a priority (P0/P1/P2); keep P0 for “must fix before release” and P1 for “fix in next cycle.”
