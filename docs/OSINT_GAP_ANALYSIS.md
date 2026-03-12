# OSINT Tool Survey: Gap Analysis

## Methodology

Analyzed 8 reference projects (httpx, tlsx, katana, webanalyze, lychee, feroxbuster, sniffnet, trippy) against domain_status's current capture. Focused on data extractable from existing connections (1 HTTP request + 1 TLS probe + DNS queries).

---

## Gap Analysis: What httpx/tlsx Capture That We Don't

### High Value, Zero Extra Connections (extract from existing HTTP response)

| Signal | Source | What httpx captures | domain_status status | Effort |
|--------|--------|---------------------|---------------------|--------|
| **Response body hash** (SHA-256) | HTTP body | `body_sha256`, `body_md5`, `body_mmh3`, `body_simhash` | **Done** (`body_sha256` on `url_status`) | Low — `sha2` already a dependency |
| **Response header hash** | HTTP headers | `header_sha256`, `header_md5`, `header_mmh3`, `header_simhash` | **Missing** | Low |
| **Content-Length** | HTTP header | `content_length` | **Done** (`content_length` on `url_status`) | Trivial |
| **Word/line count** | HTTP body | `words`, `lines` | **Done** (`body_word_count`, `body_line_count` on `url_status`) | Trivial |
| **CSP domain extraction** | CSP header + meta tags | FQDNs and registrable domains from CSP directives | **Done** (`url_csp_domains` satellite table) | Medium — httpx has ~80 lines for this |
| **CNAME chain** | DNS | `cname` records | **Done** (`url_cname_records` satellite table) | Low — hickory already supports CNAME lookup |
| **AAAA records** (IPv6) | DNS | `aaaa` addresses | **Done** (`url_ipv6_addresses` satellite table) | Low — hickory supports AAAA lookup |
| **CDN detection** | IP ranges + headers | `cdn`, `cdn_name`, `cdn_type` | **Missing** | Medium — needs IP range database |
| **HTTP version** | Response | `http2` boolean | **Done** (`http_version` on `url_status`) | Trivial — `response.version()` |
| **Content-Type** | HTTP header | `content_type` | **Done** (`content_type` on `url_status`) | Trivial |
| **Body FQDNs/domains** | HTML body | Domains extracted from body text | **Done** (`url_body_domains` satellite table, scraper-based) | Medium |
| **Redirect chain status codes** | Redirects | `chain_status_codes` per hop | **Done** (`http_status` on `url_redirect_chain`) | Low |
| **Canonical URL** | HTML `<link rel="canonical">` | Not in httpx but valuable for SEO/dedup | **Done** (`canonical_url` on `url_status`) | Trivial — already parsing HTML |
| **Meta refresh redirect** | HTML `<meta http-equiv="refresh">` | Client-side redirect detection | **Done** (`meta_refresh_url` on `url_status`) | Low |

### High Value, From TLS Probe (already making this connection)

| Signal | Source | What tlsx captures | domain_status status | Effort |
|--------|--------|---------------------|---------------------|--------|
| **Certificate chain** (full) | TLS handshake | Full chain, not just leaf | **Partial** — leaf only | Medium — already have the connection |
| **Certificate fingerprint** (SHA-256) | Cert DER | Hash of leaf cert | **Done** (`cert_fingerprint_sha256` on `url_status`) | Trivial — `sha2` already a dependency |
| **Certificate transparency SCTs** | TLS extensions | Signed Certificate Timestamps | **Missing** | Medium |

### Medium Value, Zero Extra Connections

| Signal | Source | What it reveals | domain_status status | Effort |
|--------|--------|-----------------|---------------------|--------|
| **Cookie analysis** | `Set-Cookie` headers | Security attributes (Secure, HttpOnly, SameSite), third-party domains | **Done** (`url_cookies` satellite table) | Medium |
| **DNS CAA records** | DNS | Which CAs are authorized for the domain | **Done** (`url_caa_records` satellite table) | Low — hickory supports CAA |
| **SRI hashes** | HTML `<script integrity>` | Subresource Integrity hashes for JS/CSS | **Missing** | Low |
| **Preconnect/prefetch hints** | HTML `<link rel="preconnect/dns-prefetch">` | Infrastructure dependencies | **Done** (`url_resource_hints` satellite table) | Low |
| **Web manifest** | HTML `<link rel="manifest">` | PWA configuration | **Missing** | Low |
| **`robots.txt` directives** | Would need extra fetch | Crawl rules, sitemap URLs | Not applicable (extra connection) | — |

### Lower Value or Requires Extra Connections

| Signal | Source | Notes | Recommendation |
|--------|--------|-------|----------------|
| JARM fingerprint | Multiple TLS probes with different ClientHello | Requires 10+ TLS connections | **Skip** — violates single-call constraint |
| JA3/JA3S hash | TLS ClientHello/ServerHello | Client-side is our own fingerprint (not useful); server-side needs raw handshake bytes | **Skip** — limited value |
| Virtual host detection | Extra HTTP request with different Host header | Requires extra connection | **Skip** |
| Pipeline detection | Multiple pipelined requests | Requires extra connection | **Skip** |
| WebSocket detection | `Upgrade: websocket` header in response | Very rare to see unprompted | **Low priority** |
| Screenshot | Headless browser | Completely different tool | **Skip** |

---

## Recommended Additions (Prioritized)

### Tier 1: Trivial additions -- DONE

1. ~~**Response body SHA-256 hash**~~ -- `body_sha256` on `url_status`
2. ~~**Content-Length**~~ -- `content_length` on `url_status`
3. ~~**HTTP version**~~ -- `http_version` on `url_status`
4. ~~**Word and line count**~~ -- `body_word_count`, `body_line_count` on `url_status`
5. ~~**Content-Type**~~ -- `content_type` on `url_status`
6. ~~**Canonical URL**~~ -- `canonical_url` on `url_status`
7. ~~**Certificate SHA-256 fingerprint**~~ -- `cert_fingerprint_sha256` on `url_status`
8. ~~**Redirect chain status codes**~~ -- `http_status` on `url_redirect_chain`

### Tier 2: Low-effort DNS additions -- DONE

9. ~~**CNAME chain**~~ -- `url_cname_records` satellite table (`cname_target`)
10. ~~**AAAA records**~~ (IPv6 addresses) -- `url_ipv6_addresses` satellite table (`ipv6_address`)
11. ~~**DNS CAA records**~~ -- `url_caa_records` satellite table (`flag`, `tag`, `value`)

### Tier 3: Medium-effort extractions -- DONE

12. ~~**CSP domain extraction**~~ -- `url_csp_domains` satellite table (directive, fqdn, registrable\_domain)
13. ~~**Cookie security analysis**~~ -- `url_cookies` satellite table (name, secure, http\_only, same\_site, domain, path)
14. ~~**Meta refresh detection**~~ -- `meta_refresh_url` on `url_status`
15. ~~**Preconnect/DNS-prefetch hints**~~ -- `url_resource_hints` satellite table (hint\_type, href)

Additional Tier 3 items (not in original gap analysis):
16. ~~**Certificate serial number**~~ -- `cert_serial_number` on `url_status`
17. ~~**Self-signed/wildcard/mismatched cert detection**~~ -- `cert_is_self_signed`, `cert_is_wildcard`, `cert_is_mismatched` on `url_status`
18. ~~**Body FQDN extraction**~~ -- `url_body_domains` satellite table (fqdn, registrable\_domain) using scraper HTML parser

---

## What domain_status Already Does Better Than httpx

- **Structured data extraction** (JSON-LD, Open Graph, Twitter Cards) — httpx doesn't do this
- **Social media link extraction** — httpx doesn't do this
- **Contact link extraction** (mailto/tel) — httpx doesn't do this
- **Exposed secret detection** — httpx doesn't do this (uses nuclei for that)
- **Analytics ID extraction** — httpx doesn't do this
- **WHOIS/RDAP enrichment** — httpx doesn't do this
- **Security warning analysis** — httpx has less comprehensive header analysis
- **Technology detection with categories** — httpx uses wappalyzer but doesn't store categories
- **Full certificate OID extraction** — httpx/tlsx focus on leaf cert, not all OIDs
