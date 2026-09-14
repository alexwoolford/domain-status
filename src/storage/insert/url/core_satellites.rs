//! Core vs enrichment satellite table lists (ADR 0007 write phases).

/// Core satellites inserted inside the `url_status` transaction.
///
/// Cleaned before re-insert on UPSERT so rescans do not leave stale child rows.
/// Enrichment tables are **not** listed here — they are replaced in the enrichment
/// writer transaction so readers never see an empty gap after the fact row commits.
pub(crate) const URL_STATUS_CORE_SATELLITE_TABLES: &[&str] = &[
    "url_technologies",
    "url_nameservers",
    "url_txt_records",
    "url_mx_records",
    "url_security_headers",
    "url_http_headers",
    "url_certificate_oids",
    "url_redirect_chain",
    "url_certificate_sans",
    "url_cname_records",
    "url_ipv6_addresses",
    "url_caa_records",
    "url_csp_domains",
    "url_cookies",
    "url_resource_hints",
    "url_script_hosts",
    "url_security_txt",
    "url_robots_txt",
    "url_robots_directives",
];

/// Enrichment satellites inserted after the `url_status` transaction commits.
///
/// DELETE + INSERT share one writer transaction in `insert_enrichment_data`.
/// `url_jwt_claims` is omitted: those rows cascade-delete from `url_exposed_secrets`.
pub(crate) const URL_STATUS_ENRICHMENT_SATELLITE_TABLES: &[&str] = &[
    "url_analytics_ids",
    "url_structured_data",
    "url_social_media_links",
    "url_contact_links",
    "url_exposed_secrets",
    "url_partial_failures",
    "url_favicons",
    "url_geoip",
    "url_whois",
];

const fn core_and_enrichment_overlap() -> bool {
    let mut i = 0;
    while i < URL_STATUS_CORE_SATELLITE_TABLES.len() {
        if crate::const_str::slice_contains(
            URL_STATUS_ENRICHMENT_SATELLITE_TABLES,
            URL_STATUS_CORE_SATELLITE_TABLES[i],
        ) {
            return true;
        }
        i += 1;
    }
    false
}

const _: () = assert!(
    !core_and_enrichment_overlap(),
    "core and enrichment satellite lists must not overlap"
);

/// Union of core + enrichment child tables (core first).
#[cfg(test)]
pub(crate) fn url_status_satellite_tables() -> impl Iterator<Item = &'static str> {
    URL_STATUS_CORE_SATELLITE_TABLES
        .iter()
        .copied()
        .chain(URL_STATUS_ENRICHMENT_SATELLITE_TABLES.iter().copied())
}
