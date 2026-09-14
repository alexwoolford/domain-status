//! Page-structure core satellites (CSP, cookies, well-known, hints, script hosts).

use crate::storage::insert::utils::build_batch_insert_query;

/// Inserts CSP domains into `url_csp_domains` table.
pub(crate) async fn insert_csp_domains(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    domains: &[(String, String, Option<String>)],
) -> Result<(), sqlx::Error> {
    if domains.is_empty() {
        return Ok(());
    }
    let query = build_batch_insert_query(
        "url_csp_domains",
        &["url_status_id", "directive", "fqdn", "registrable_domain"],
        domains.len(),
        Some("ON CONFLICT(url_status_id, directive, fqdn) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (directive, fqdn, reg_domain) in domains {
        qb = qb
            .bind(url_status_id)
            .bind(directive)
            .bind(fqdn)
            .bind(reg_domain);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts cookie security info into `url_cookies` table.
///
/// Unique on `(url_status_id, cookie_name)` only — browsers key cookies by
/// name + Domain + Path, so two `Set-Cookie` headers with the same name collapse
/// here (last write wins, including `domain` / `path`).
pub(crate) async fn insert_cookies(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    cookies: &[crate::storage::CookieInfo],
) -> Result<(), sqlx::Error> {
    if cookies.is_empty() {
        return Ok(());
    }
    let query = build_batch_insert_query(
        "url_cookies",
        &[
            "url_status_id",
            "cookie_name",
            "secure",
            "http_only",
            "same_site",
            "domain",
            "path",
        ],
        cookies.len(),
        Some(
            "ON CONFLICT(url_status_id, cookie_name) DO UPDATE SET \
             secure=excluded.secure, http_only=excluded.http_only, \
             same_site=excluded.same_site, domain=excluded.domain, path=excluded.path",
        ),
    );
    let mut qb = sqlx::query(&query);
    for c in cookies {
        qb = qb
            .bind(url_status_id)
            .bind(&c.name)
            .bind(c.secure)
            .bind(c.http_only)
            .bind(&c.same_site)
            .bind(&c.domain)
            .bind(&c.path);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts parsed `security.txt` into `url_security_txt`.
pub(crate) async fn insert_security_txt(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    data: Option<&crate::fetch::well_known::SecurityTxtData>,
) -> Result<(), sqlx::Error> {
    let Some(data) = data else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO url_security_txt (
            url_status_id, source_url, http_status, contacts, expires, encryption,
            acknowledgments, preferred_languages, canonical, policy, hiring, raw_body
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url_status_id) DO UPDATE SET
            source_url=excluded.source_url,
            http_status=excluded.http_status,
            contacts=excluded.contacts,
            expires=excluded.expires,
            encryption=excluded.encryption,
            acknowledgments=excluded.acknowledgments,
            preferred_languages=excluded.preferred_languages,
            canonical=excluded.canonical,
            policy=excluded.policy,
            hiring=excluded.hiring,
            raw_body=excluded.raw_body",
    )
    .bind(url_status_id)
    .bind(&data.source_url)
    .bind(i64::from(data.http_status))
    .bind(data.contacts.join("\n"))
    .bind(&data.expires)
    .bind(data.encryption.join("\n"))
    .bind(data.acknowledgments.join("\n"))
    .bind(&data.preferred_languages)
    .bind(data.canonical.join("\n"))
    .bind(data.policy.join("\n"))
    .bind(data.hiring.join("\n"))
    .bind(&data.raw_body)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Inserts parsed `robots.txt` parent row and directives.
pub(crate) async fn insert_robots_txt(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    data: Option<&crate::fetch::well_known::RobotsTxtData>,
) -> Result<(), sqlx::Error> {
    let Some(data) = data else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO url_robots_txt (url_status_id, http_status, raw_body)
         VALUES (?, ?, ?)
         ON CONFLICT(url_status_id) DO UPDATE SET
            http_status=excluded.http_status,
            raw_body=excluded.raw_body",
    )
    .bind(url_status_id)
    .bind(i64::from(data.http_status))
    .bind(&data.raw_body)
    .execute(&mut **tx)
    .await?;
    if data.directives.is_empty() {
        return Ok(());
    }
    let query = build_batch_insert_query(
        "url_robots_directives",
        &["url_status_id", "directive", "value"],
        data.directives.len(),
        Some("ON CONFLICT(url_status_id, directive, value) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (directive, value) in &data.directives {
        qb = qb.bind(url_status_id).bind(directive).bind(value);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts script `src` host inventory into `url_script_hosts`.
pub(crate) async fn insert_script_hosts(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hosts: &[crate::storage::ScriptHostInfo],
) -> Result<(), sqlx::Error> {
    if hosts.is_empty() {
        return Ok(());
    }
    let query = build_batch_insert_query(
        "url_script_hosts",
        &[
            "url_status_id",
            "host",
            "registrable_domain",
            "is_first_party",
        ],
        hosts.len(),
        Some(
            "ON CONFLICT(url_status_id, host) DO UPDATE SET \
             registrable_domain=excluded.registrable_domain, \
             is_first_party=excluded.is_first_party",
        ),
    );
    let mut qb = sqlx::query(&query);
    for h in hosts {
        qb = qb
            .bind(url_status_id)
            .bind(&h.host)
            .bind(&h.registrable_domain)
            .bind(h.is_first_party);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}

/// Inserts resource hints into `url_resource_hints` table. `hint_type` may be
/// preconnect, dns-prefetch, preload, prefetch, or modulepreload.
pub(crate) async fn insert_resource_hints(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    url_status_id: i64,
    hints: &[(String, String)],
) -> Result<(), sqlx::Error> {
    if hints.is_empty() {
        return Ok(());
    }
    let query = build_batch_insert_query(
        "url_resource_hints",
        &["url_status_id", "hint_type", "href"],
        hints.len(),
        Some("ON CONFLICT(url_status_id, hint_type, href) DO NOTHING"),
    );
    let mut qb = sqlx::query(&query);
    for (hint_type, href) in hints {
        qb = qb
            .bind(url_status_id)
            .bind(hint_type.to_ascii_lowercase())
            .bind(href);
    }
    qb.execute(&mut **tx).await?;
    Ok(())
}
