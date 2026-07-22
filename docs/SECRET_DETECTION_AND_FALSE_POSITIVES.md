# Secret detection and false positives

The `url_exposed_secrets` table stores findings from gitleaks-style rules run over live HTML. Because we scan **web pages** (not just source files), some findings are **public identifiers** or **anti-crawling artifacts**, not real credentials. This doc describes known false-positive patterns and how to triage.

## What can be false positives

- **Public identifiers**: Form/embed IDs (e.g. `data-hubspot-form="uuid"`), build IDs, CSRF tokens in HTML attributes, analytics or tag-manager IDs that are meant to be public.
- **Anti-crawling / CDN**: Content injected by Cloudflare (email obfuscation, challenge pages) or similar that contains provider names and hex/UUID patterns in non-secret contexts.
- **Location + rule**: `location = 'data_attribute'` with a rule that matches “provider name + UUID” often indicates a form/embed ID, not an API key.

## Known rule + context patterns

| Pattern | Rule(s) | Why it’s a false positive | Mitigation |
|--------|---------|---------------------------|------------|
| `data-hubspot-form="uuid"` | hubspot-api-key | Form/embed ID, not API key | Allowlisted in `config/gitleaks.overrides.toml` (line contains `data-hubspot-form=` or `data-hubspot-form-id=`) |
| Cloudflare email obfuscation (40-char hex) | sourcegraph-access-token | `email-protection#`, `data-cfemail=`, `__cf_email__` | Allowlisted in overrides |
| HTML `id="[40 hex]"` (e.g. Wix build) | sourcegraph-access-token | Build/instance ID | Allowlisted in overrides |
| Other anti-crawling / bot pages | sourcegraph-access-token, etc. | Bot/challenge HTML can contain “sourcegraph” + hex | Partial; add narrow allowlist regexes if a pattern recurs |

## How to triage

- Use **`location`** and **`context`**: `inline_script`, `url_parameter`, and `meta_tag` are more likely to be real secrets; `data_attribute` and `html_body` often contain public IDs or CDN content.
- Prefer **Critical/High** findings with distinctive token prefixes (`AKIA`, `SG.`, `shpat_`, `sk-`, `ghp_`). Treat `gcp-api-key` (Low) as a public client identifier inventory, not a leak.
- Inspect **`context`**: Look for `data-*-form`, `id="..."`, `email-protection#`, or other HTML patterns that indicate a public identifier or obfuscation.
- For high-confidence secrets, prefer findings where the value has a known token format (prefix, length) and the context does not match the patterns above.

## External scripts

When `--scan-external-scripts` is enabled, only **first-party** `<script src>` bundles are fetched (same registrable domain as the page). Known third-party CDNs (Stripe.js, Cookiebot, Google Analytics, etc.) are skipped because they dominate false positives.

## Audit queries

Summary by rule and location:

```sql
SELECT es.secret_type, es.location, es.severity,
       COUNT(*) AS cnt,
       COUNT(DISTINCT es.url_status_id) AS domains
FROM url_exposed_secrets es
JOIN url_status us ON es.url_status_id = us.id
GROUP BY es.secret_type, es.location, es.severity
ORDER BY cnt DESC, es.secret_type, es.location;
```

Sample context for a given rule (e.g. hubspot-api-key):

```sql
SELECT us.final_domain, es.secret_type, es.location, es.matched_value, es.context
FROM url_exposed_secrets es
JOIN url_status us ON es.url_status_id = us.id
WHERE es.secret_type = 'hubspot-api-key'
ORDER BY us.final_domain
LIMIT 50;
```

## Overrides

Web-specific allowlists live in `config/gitleaks.overrides.toml` and are merged at load time so they are not overwritten when refreshing upstream `config/gitleaks.toml`. Add new allowlists there for clear, semantic patterns (e.g. form/embed ID attributes), and add unit tests in `src/parse/secrets.rs` for each new allowlist.

For a full audit of secret types (legit vs false positive) and the fixes applied, see [SECRET_DETECTION_NOTES.md](SECRET_DETECTION_NOTES.md).
