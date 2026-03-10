# Security

## Do not commit sensitive or scan artifacts

- **Never commit** `.db` files, export files (CSV, JSONL, or Parquet from scans), or `.env` (or other env files containing secrets). These are listed in `.gitignore`; keep them out of version control.
- **Exposed secrets detected on scanned sites** and all collected data (URLs, headers) are **stored and logged in full**. No redaction is applied; this is a data collection tool. The security boundary is: do not commit `.db` files or export files (CSV/JSONL/Parquet), and protect them and config with file permissions.

## GitHub secret scanning

- **`config/gitleaks.toml`** contains upstream Gitleaks allowlist literals (known example/test keys). Those strings are used so that when we scan a page containing one of them, we do not report it as a finding; they are not project secrets. This path is excluded from GitHub secret scanning via `.github/secret_scanning.yml` so that those allowlist entries do not generate alerts.

For full security and secret-management details (gitleaks, pre-commit, CI, environment variables), see [README.md – Security & Secret Management](README.md#-security--secret-management).

## Security posture and remediation

- **Transport trust:** Page-fetch HTTP clients use strict TLS (see [ADR 0003](docs/adr/0003-tls-capture-versus-validation.md)); TLS capture for observation uses a separate path in `src/tls/`.
- **Prioritized actions and threat model:** [docs/SECURITY_REMEDIATION_ROADMAP.md](docs/SECURITY_REMEDIATION_ROADMAP.md) (links to threat model, secret retention audit, and supply chain posture).
