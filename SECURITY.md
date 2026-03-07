# Security

## Do not commit sensitive or scan artifacts

- **Never commit** `.db` files, export files (CSV, JSONL, or Parquet from scans), or `.env` (or other env files containing secrets). These are listed in `.gitignore`; keep them out of version control.
- **Exposed secrets detected on scanned sites** are **redacted** before storage and again at export. Only redacted forms (e.g. `redacted(AKIA...xxxx,len=...,sha256=...)`) are stored in the database and written to exports. Raw matched secrets from other sites are not persisted or published.

## GitHub secret scanning

- **`config/gitleaks.toml`** contains upstream Gitleaks allowlist literals (known example/test keys). Those strings are used so that when we scan a page containing one of them, we do not report it as a finding; they are not project secrets. This path is excluded from GitHub secret scanning via `.github/secret_scanning.yml` so that those allowlist entries do not generate alerts.

For full security and secret-management details (gitleaks, pre-commit, CI, environment variables), see [README.md – Security & Secret Management](README.md#-security--secret-management).
