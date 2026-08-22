# Secret detection and false positives

The `url_exposed_secrets` table stores findings from gitleaks-style rules run over live HTML. Because we scan **web pages** (not just source files), some findings are **public identifiers** or **anti-crawling artifacts**, not real credentials. This doc describes known false-positive patterns and how to triage.

## Mitigation principles

Prefer maintainable fixes over growing per-site exception lists:

1. **Upstream distinctive shapes** — keep well-scoped Gitleaks rules (e.g. Dropbox `sl.…` / long-lived); disable catch-alls that only match “provider name + short alnum”.
2. **Same-id rule replace** in `config/gitleaks.overrides.toml` when the upstream regex is the bug (see `sourcegraph-access-token`, `square-access-token`, `datadog-access-token`).
3. **Structural plausibility** in `web_rule_match_is_plausible` (entropy/length for `generic-api-key`, camelCase reject for LinkedIn ids, etc.), or `web_rule_match_is_plausible_in_context` when the disambiguating signal sits outside the capture group (e.g. Datadog identity markers required near bare `apiKey` hex).
4. **Severity demotion** when the match is real but public/temporary (e.g. `X-Amz-Credential=` → Low), still stored for inventory.
5. **Allowlists** only for product-format public-by-design IDs (Weglot `wg_…`, App Insights `instrumentationKey`, HubSpot form UUIDs) — not site names or one-off URL trivia.

## What can be false positives

- **Public identifiers**: Form/embed IDs (e.g. `data-hubspot-form="uuid"`), build IDs, CSRF tokens in HTML attributes, analytics or tag-manager IDs that are meant to be public.
- **Anti-crawling / CDN**: Content injected by Cloudflare (email obfuscation, challenge pages) or similar that contains provider names and hex/UUID patterns in non-secret contexts.
- **Location + rule**: `location = 'data_attribute'` with a rule that matches “provider name + UUID” often indicates a form/embed ID, not an API key.
- **Binary noise**: Prefixes like `EAAA` / `EAAC` inside WebP or other binary can look like Square/Facebook tokens; we require distinctive prefixes or assignment context.

## Known rule + context patterns

| Pattern | Rule(s) | Why it’s a false positive | Mitigation |
|--------|---------|---------------------------|------------|
| `data-hubspot-form="uuid"` | hubspot-api-key | Form/embed ID, not API key | Allowlisted (`data-hubspot-form=`, `data-hubspot-form-id=`) |
| `x-hubspot-correlation-id: uuid` | hubspot-api-key | Request correlation header, not API key | Allowlisted (`x-hubspot-correlation-id`) |
| `hubspotFormId*` / `hubspot_button_id` / `hubspotSignupguid` / `hubspotID` | hubspot-api-key | Public form/widget UUID | Allowlisted (form/button/guid/signup name shapes) |
| `app.powerbi.com/view?r=eyJrIjoi…` | grafana-api-key | Power BI embed token shares Grafana's `eyJrIjoi` prefix | Allowlisted (`powerbi.com`) |
| `wg_<32 hex>` | generic-api-key | Weglot public widget key | Allowlisted (`^wg_[0-9a-f]{32}$`) |
| `instrumentationKey:` / `InstrumentationKey=` | generic-api-key | Azure App Insights browser SDK public key | Allowlisted |
| `link_type` / `linkType` + `"key":"<hex\|uuid>"` | generic-api-key | Prismic/CMS document UUID | Allowlisted (`link[_]?type\s*:`) |
| React/SVG `key:"<32–40 hex>"` | generic-api-key | Framework reconciliation / CMS bare `key` | Allowlisted (bare `key` property only; not `apiKey`) |
| `botSignalToken:` | generic-api-key | Public anti-bot challenge token | Allowlisted |
| `X-Amz-Credential=AKIA\|ASIA…` | aws-access-token | Pre-signed URL temporary credential ID | Severity demoted to **Low** (still stored) |
| `"datadogVersion":"<40 hex>"` | datadog-access-token | Build hash, not API key | Rule replaced: credential assignment only |
| Bare `apiKey:"<hex>"` (Bugsnag, Amplitude, Algolia, …) | datadog-access-token | Regex still matches generic `apiKey`/`appKey`; many SDKs use that shape | Keep only when nearby text identifies Datadog (`datadog`, `dd_api`, `dd_rum`, …) |
| `EAAA…` in binary | square-access-token | WebP/binary collision | Rule replaced: `sq0atp-` only |
| Bare `EAA[MC]…` in binary | facebook-page-access-token | Binary collision | Rule replaced: `access_token=` context |
| `…discord…` near 32-char CSS/URL token | discord-client-secret | Upstream allows `,` as operator | Rule replaced: `discord*client*secret=` assignment only |
| 15-char near “dropbox” | dropbox-api-token | JS identifier (e.g. `theChampSiteUrl`) | Rule disabled; use long/short-lived Dropbox rules |
| camelCase near “linkedin” (e.g. `thumbnailWidth`) | linkedin-client-id/secret | JS property name | Plausibility: reject lowercase-starting camelCase |
| Cloudflare email obfuscation (40-char hex) | sourcegraph-access-token | `email-protection#`, `data-cfemail=`, `__cf_email__` | Allowlisted in overrides |
| Firebase / Maps / browser `AIza…` | gcp-api-key | Often **public client** keys embedded in JS by design | Treat as **Low** inventory; confirm restriction (HTTP referrer / API) before escalating |
| Google AI Studio / **Gemini** API keys (`AIza…`) | gcp-api-key | Same shape as Maps/Firebase browser keys; there is **no** separate `gemini-api-key` rule | Detected and stored as `gcp-api-key` at **Low**; triage like other Google client keys |
| Netlify CWV / shop / session JWTs | jwt | Public or short-lived client tokens | Keep claims in `url_jwt_claims`; severity usually Low — not a private signing key |
| HTML `id="[40 hex]"` (e.g. Wix build) | sourcegraph-access-token | Build/instance ID | Allowlisted in overrides |

## How to triage

- Use **`location`** and **`context`**: `inline_script`, `json_ld`, `url_parameter`, `set_cookie`, and `external_script:…` are more likely to be real secrets; `data_attribute` and `html_body` often contain public IDs or CDN content.
- Prefer **Critical/High** findings with distinctive token prefixes (`AKIA` outside Amz-Credential, `SG.`, `shpat_`, `sk_live_`, `ghp_`, `glc_`, `sk-…T3BlbkFJ…` OpenAI, `sk-ant-api03-` / `sk-ant-admin01-` Anthropic). Treat `gcp-api-key` (including Gemini/AI Studio `AIza…` keys), `jwt`, and Amz-Credential AWS IDs as **Low** inventory, not urgent leaks.
- When assessing possible misses, join `url_status.body_truncated` and `external_scripts_eligible` / `external_scripts_scanned` (incomplete scan when truncated or eligible > scanned).
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

Web-specific rule replaces and allowlists live in `config/gitleaks.overrides.toml` and are merged at load time so they are not overwritten when refreshing upstream `config/gitleaks.toml`. Prefer same-id `[[rules]]` replaces and structural filters for broad FPs; add `[[append]]` allowlists only for clear product-format public IDs. Add unit tests in `src/parse/secrets.rs` for each new mitigation.

## Related: HTTP failure labeling

Reqwest **Connect** failures often embed `dns error` in the error chain (A/AAAA during dial). Those are labeled `HTTP request connect error`, not `DNS NS lookup error`. NS/TXT/MX labels are reserved for enrichment DNS lookups (`NetError`), not for reclassifying HTTP connect failures whose message happens to contain the substring `dns`.
