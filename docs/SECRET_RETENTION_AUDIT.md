# Secret Retention Audit

This document records where exposed-secret and other sensitive data are redacted before persistence or export, and confirms that raw secrets are not stored or logged.

**Last reviewed:** 2026-03-01 (Security Posture Report implementation).

---

## Exposed secrets (matched_value, context)

### Insert path

- **File:** [src/storage/insert/enrichment/secrets.rs](src/storage/insert/enrichment/secrets.rs)
- **Behavior:** Before each `INSERT` into `url_exposed_secrets`, the code calls:
  - `redact_exposed_secret_value(&secret.matched_value)` → stored in `matched_value` column
  - `redact_exposed_secret_context(&secret.context, &secret.matched_value)` → stored in `context` column
- **Redaction format:** `redacted(len=N,sha256=HEX)` or prefix/suffix plus length and SHA256 (see [src/parse/secrets.rs](src/parse/secrets.rs) `redact_exposed_secret_value`). Raw secret text is never written to the database.

### Export path

- **File:** [src/export/row.rs](src/export/row.rs) (build of `ExportRow` from DB rows)
- **Behavior:** When reading `url_exposed_secrets` for export, the code re-applies:
  - `redact_exposed_secret_value(&matched_value)` and `redact_exposed_secret_context(ctx, &matched_value)` to the values read from the DB before building `ExposedSecretRecord` for CSV/JSONL/Parquet.
- **Defense in depth:** Even if the DB contained raw values (e.g. from an older migration or bug), the export pipeline would still redact before writing to export files.

### Export formats

- **CSV, JSONL, Parquet:** All use the export row type that carries the redacted `matched_value` and `context` produced in the step above. No export format receives or writes raw secret text.

---

## URLs and headers (logging and failure storage)

- **Request/response logging:** [src/fetch/handler/request.rs](src/fetch/handler/request.rs) uses `scrub_url()` and `scrub_headers()` before passing URLs and headers to debug logs and into stored records. Userinfo, query, and fragment are stripped from URLs; sensitive header values are replaced with `[redacted]`.
- **Failure records:** [src/storage/failure/record.rs](src/storage/failure/record.rs) uses `scrub_url()` and `scrub_headers()` when building failure records for the database. No raw credentials or query tokens are stored.
- **CLI/path warnings:** [src/cli.rs](src/cli.rs) uses `scrub_path()` when logging path-related errors so full filesystem paths are not emitted.

---

## Conclusion

- **Database:** Only redacted forms of exposed secrets (and scrubbed URLs/headers) are stored.
- **Exports:** CSV, JSONL, and Parquet receive redacted secret values and context from the export row builder, which applies redaction when reading from the DB.
- **Logs:** URLs and sensitive headers are scrubbed before being passed to tracing or stored in failure records.

No changes were required; the audit confirms existing behavior. Future changes that add new persistence or logging of secret-like data should apply the same redaction (or scrub) before write.
