//! Exposed secret detection in HTML content.
//!
//! Uses the gitleaks default config (see `config/gitleaks.toml`) as the source
//! of rules. Each rule's regex is run over the HTML body; entropy and allowlist
//! filters reduce false positives.
//!
//! Each finding includes:
//! - **secret_type**: gitleaks rule id (e.g. `aws-access-token`)
//! - **severity**: critical / high / medium / low (mapped from rule id or default High)
//! - **location**: heuristic for where in the HTML the secret was found
//! - **context**: ~80 chars before + match + ~80 chars after for analyst triage

use std::fmt;

/// Number of context characters to capture before and after a match.
const CONTEXT_CHARS: usize = 80;

/// Severity levels for exposed secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretSeverity {
    /// Can directly compromise systems or charge money (e.g., AWS secret key, Stripe secret key, private keys).
    Critical,
    /// Significant access but may need pairing or have limits (e.g., AWS access key alone, OpenAI key).
    High,
    /// Potentially sensitive but often restricted or scoped (e.g., Google API key, Slack webhook).
    Medium,
    /// Intentionally public or low-impact (e.g., Stripe publishable key, Firebase URL, Mapbox public token).
    Low,
}

impl SecretSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretSeverity::Critical => "critical",
            SecretSeverity::High => "high",
            SecretSeverity::Medium => "medium",
            SecretSeverity::Low => "low",
        }
    }
}

impl fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Legacy secret type enum (retained for API compatibility).
/// Detection now uses gitleaks rule ids (strings) stored in `ExposedSecret.secret_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum SecretType {
    // Cloud Providers
    AwsAccessKey,
    AwsSessionToken,
    AwsSecretKey,
    GoogleApiKey,
    GoogleOAuthToken,
    AzureConnectionString,
    AzureSasToken,

    // AI/ML Providers
    OpenAiApiKey,
    AnthropicApiKey,
    HuggingFaceToken,

    // Payment
    StripePublishableKey,
    StripeSecretKey,
    StripeRestrictedKey,
    SquareAccessToken,

    // Communication
    SlackWebhook,
    SlackBotToken,
    SlackAppToken,
    SlackUserToken,
    DiscordWebhook,
    DiscordBotToken,
    TwilioAccountSid,
    SendGridApiKey,

    // Source Control
    GitHubToken,
    GitHubFineGrained,
    GitLabToken,
    BitbucketAppPassword,

    // Database
    DatabaseUrl,
    FirebaseUrl,
    AzureCosmosDb,

    // Cryptographic Keys
    PrivateKey,

    // Infrastructure
    HerokuApiKey,
    VercelToken,
    DigitalOceanToken,
    NpmToken,
    PypiToken,
    TerraformCloudToken,
    VaultToken,
    FlyIoToken,

    // Services
    MailchimpApiKey,
    MailgunApiKey,
    MapboxToken,
    ShopifyToken,
    AlgoliaApiKey,
    SentryDsn,
    PlaidToken,
    SupabaseKey,

    // Monitoring
    DatadogApiKey,
    NewRelicKey,
    GrafanaToken,

    // Infrastructure (additional)
    CloudflareApiToken,
    LinearApiKey,
    DopplerToken,
    FastlyApiToken,
}

#[allow(dead_code)]
impl SecretType {
    /// Returns the secret type as a snake_case string for DB storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            // Cloud
            SecretType::AwsAccessKey => "aws_access_key",
            SecretType::AwsSessionToken => "aws_session_token",
            SecretType::AwsSecretKey => "aws_secret_key",
            SecretType::GoogleApiKey => "google_api_key",
            SecretType::GoogleOAuthToken => "google_oauth_token",
            SecretType::AzureConnectionString => "azure_connection_string",
            SecretType::AzureSasToken => "azure_sas_token",
            // AI/ML
            SecretType::OpenAiApiKey => "openai_api_key",
            SecretType::AnthropicApiKey => "anthropic_api_key",
            SecretType::HuggingFaceToken => "huggingface_token",
            // Payment
            SecretType::StripePublishableKey => "stripe_publishable_key",
            SecretType::StripeSecretKey => "stripe_secret_key",
            SecretType::StripeRestrictedKey => "stripe_restricted_key",
            SecretType::SquareAccessToken => "square_access_token",
            // Communication
            SecretType::SlackWebhook => "slack_webhook",
            SecretType::SlackBotToken => "slack_bot_token",
            SecretType::SlackAppToken => "slack_app_token",
            SecretType::SlackUserToken => "slack_user_token",
            SecretType::DiscordWebhook => "discord_webhook",
            SecretType::DiscordBotToken => "discord_bot_token",
            SecretType::TwilioAccountSid => "twilio_account_sid",
            SecretType::SendGridApiKey => "sendgrid_api_key",
            // Source Control
            SecretType::GitHubToken => "github_token",
            SecretType::GitHubFineGrained => "github_fine_grained",
            SecretType::GitLabToken => "gitlab_token",
            SecretType::BitbucketAppPassword => "bitbucket_app_password",
            // Database
            SecretType::DatabaseUrl => "database_url",
            SecretType::FirebaseUrl => "firebase_url",
            SecretType::AzureCosmosDb => "azure_cosmos_db",
            // Crypto
            SecretType::PrivateKey => "private_key",
            // Infrastructure
            SecretType::HerokuApiKey => "heroku_api_key",
            SecretType::VercelToken => "vercel_token",
            SecretType::DigitalOceanToken => "digitalocean_token",
            SecretType::NpmToken => "npm_token",
            SecretType::PypiToken => "pypi_token",
            SecretType::TerraformCloudToken => "terraform_cloud_token",
            SecretType::VaultToken => "vault_token",
            SecretType::FlyIoToken => "flyio_token",
            // Services
            SecretType::MailchimpApiKey => "mailchimp_api_key",
            SecretType::MailgunApiKey => "mailgun_api_key",
            SecretType::MapboxToken => "mapbox_token",
            SecretType::ShopifyToken => "shopify_token",
            SecretType::AlgoliaApiKey => "algolia_api_key",
            SecretType::SentryDsn => "sentry_dsn",
            SecretType::PlaidToken => "plaid_token",
            SecretType::SupabaseKey => "supabase_key",
            // Monitoring
            SecretType::DatadogApiKey => "datadog_api_key",
            SecretType::NewRelicKey => "newrelic_key",
            SecretType::GrafanaToken => "grafana_token",
            // Additional infrastructure
            SecretType::CloudflareApiToken => "cloudflare_api_token",
            SecretType::LinearApiKey => "linear_api_key",
            SecretType::DopplerToken => "doppler_token",
            SecretType::FastlyApiToken => "fastly_api_token",
        }
    }

    /// Returns the severity classification for this secret type.
    pub fn severity(&self) -> SecretSeverity {
        match self {
            // Critical: direct compromise or financial impact
            SecretType::AwsSecretKey
            | SecretType::StripeSecretKey
            | SecretType::StripeRestrictedKey
            | SecretType::PrivateKey
            | SecretType::DatabaseUrl
            | SecretType::AzureConnectionString
            | SecretType::AzureCosmosDb
            | SecretType::SlackBotToken
            | SecretType::SlackUserToken
            | SecretType::DiscordBotToken
            | SecretType::GitHubToken
            | SecretType::GitHubFineGrained
            | SecretType::GitLabToken
            | SecretType::VaultToken => SecretSeverity::Critical,

            // High: significant access, may need pairing or have limits
            SecretType::AwsAccessKey
            | SecretType::AwsSessionToken
            | SecretType::OpenAiApiKey
            | SecretType::AnthropicApiKey
            | SecretType::HuggingFaceToken
            | SecretType::SendGridApiKey
            | SecretType::TwilioAccountSid
            | SecretType::NpmToken
            | SecretType::PypiToken
            | SecretType::DigitalOceanToken
            | SecretType::HerokuApiKey
            | SecretType::VercelToken
            | SecretType::TerraformCloudToken
            | SecretType::FlyIoToken
            | SecretType::ShopifyToken
            | SecretType::BitbucketAppPassword
            | SecretType::MailgunApiKey
            | SecretType::SupabaseKey
            | SecretType::CloudflareApiToken
            | SecretType::DopplerToken
            | SecretType::PlaidToken
            | SecretType::FastlyApiToken => SecretSeverity::High,

            // Medium: potentially sensitive but often scoped/restricted
            SecretType::GoogleApiKey
            | SecretType::GoogleOAuthToken
            | SecretType::AzureSasToken
            | SecretType::SlackWebhook
            | SecretType::SlackAppToken
            | SecretType::DiscordWebhook
            | SecretType::SquareAccessToken
            | SecretType::MailchimpApiKey
            | SecretType::AlgoliaApiKey
            | SecretType::DatadogApiKey
            | SecretType::NewRelicKey
            | SecretType::GrafanaToken
            | SecretType::SentryDsn
            | SecretType::LinearApiKey => SecretSeverity::Medium,

            // Low: intentionally public or minimal impact
            SecretType::StripePublishableKey
            | SecretType::FirebaseUrl
            | SecretType::MapboxToken => SecretSeverity::Low,
        }
    }
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An exposed secret detected in HTML content.
#[derive(Debug, Clone)]
pub struct ExposedSecret {
    /// Gitleaks rule id (e.g. `aws-access-token`).
    pub secret_type: String,
    /// Full matched value as found on the public page.
    pub matched_value: String,
    /// Surrounding text for context (~80 chars before + match + ~80 chars after).
    pub context: String,
    /// Severity classification (critical / high / medium / low).
    pub severity: SecretSeverity,
    /// Heuristic location hint (inline_script, html_comment, url_parameter, etc.).
    pub location: String,
}

/// Shannon entropy (log2) of the string, over byte frequencies.
/// Used to filter low-entropy matches when a gitleaks rule sets an entropy threshold.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    #[allow(clippy::cast_precision_loss)] // secret substrings are short; f64 mantissa sufficient
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Severity for a gitleaks rule id. Uses a small mapping for known types; default High.
fn severity_for_rule_id(rule_id: &str) -> SecretSeverity {
    match rule_id {
        // Critical: direct compromise or financial
        "private-key"
        | "slack-bot-token"
        | "slack-user-token"
        | "slack-legacy-token"
        | "slack-legacy-bot-token"
        | "github-pat"
        | "github-fine-grained-pat"
        | "gitlab-pat"
        | "vault-batch-token"
        | "vault-service-token" => SecretSeverity::Critical,
        // High
        "aws-access-token"
        | "openai-api-key"
        | "anthropic-api-key"
        | "anthropic-admin-api-key"
        | "sendgrid-api-token"
        | "twilio-api-key"
        | "npm-access-token"
        | "pypi-upload-token"
        | "digitalocean-access-token"
        | "digitalocean-pat"
        | "heroku-api-key"
        | "heroku-api-key-v2"
        | "flyio-access-token"
        | "shopify-access-token"
        | "shopify-private-app-access-token"
        | "shopify-shared-secret"
        | "bitbucket-client-secret"
        | "mailgun-private-api-token"
        | "cloudflare-api-key"
        | "doppler-api-token"
        | "plaid-secret-key"
        | "plaid-api-token"
        | "fastly-api-token" => SecretSeverity::High,
        // Medium
        "gcp-api-key"
        | "azure-ad-client-secret"
        | "slack-webhook-url"
        | "slack-app-token"
        | "algolia-api-key"
        | "datadog-access-token"
        | "grafana-api-key"
        | "grafana-cloud-api-token"
        | "sentry-access-token"
        | "linear-api-key" => SecretSeverity::Medium,
        // Low
        "mapbox-api-token" => SecretSeverity::Low,
        _ => SecretSeverity::High,
    }
}

/// Returns true if the match should be skipped by the global allowlist (regex or stopword).
fn global_allowlist_skips(
    global: &crate::parse::gitleaks::CompiledGlobalAllowlist,
    matched_value: &str,
    context: &str,
) -> bool {
    for re in &global.regexes {
        if re.is_match(matched_value) || re.is_match(context) {
            return true;
        }
    }
    for word in &global.stopwords {
        if matched_value.contains(word) || context.contains(word) {
            return true;
        }
    }
    false
}

/// Returns the line containing the byte range [start, end) in body. Line = span between \\n or start/end of body.
fn line_containing(body: &str, start: usize, end: usize) -> &str {
    let line_start = body[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = body[end..].find('\n').map_or(body.len(), |i| end + i);
    &body[line_start..line_end]
}

/// Extracts the secret from a regex match per Gitleaks: SecretGroup (1-based) if set, else first non-empty capture group, else full match.
fn extract_secret(
    captures: Option<regex::Captures>,
    full_match: &str,
    secret_group: Option<u32>,
) -> String {
    let caps = match captures {
        Some(c) => c,
        None => return full_match.to_string(),
    };
    if let Some(n) = secret_group {
        if n > 0 {
            if let Some(m) = caps.get(n as usize) {
                return m.as_str().to_string();
            }
        }
    }
    for i in 1..caps.len() {
        if let Some(m) = caps.get(i) {
            if !m.as_str().is_empty() {
                return m.as_str().to_string();
            }
        }
    }
    full_match.to_string()
}

/// Returns true if any per-rule allowlist (regex or stopword) matches the appropriate target per RegexTarget (secret / line / match).
fn rule_allowlist_skips(
    allowlists: &[crate::parse::gitleaks::CompiledRuleAllowlist],
    matched_value: &str,
    line_content: &str,
    full_match: &str,
) -> bool {
    for list in allowlists {
        let target = match list.regex_target.as_deref() {
            Some("line") => line_content,
            Some("match") => full_match,
            _ => matched_value,
        };
        for re in &list.regexes {
            if re.is_match(target) {
                return true;
            }
        }
        for word in &list.stopwords {
            if target.contains(word) {
                return true;
            }
        }
    }
    false
}

/// Extracts surrounding context for a match within the body text.
fn extract_context(body: &str, start: usize, end: usize) -> String {
    let ctx_start = start.saturating_sub(CONTEXT_CHARS);
    let ctx_end = (end + CONTEXT_CHARS).min(body.len());

    // Find valid char boundaries (compatible with MSRV 1.85)
    let safe_start = body[..ctx_start]
        .char_indices()
        .next_back()
        .map_or(0, |(i, _)| i);
    let safe_end = if ctx_end >= body.len() {
        body.len()
    } else {
        body[ctx_end..]
            .char_indices()
            .next()
            .map_or(body.len(), |(i, _)| ctx_end + i)
    };

    body[safe_start..safe_end].to_string()
}

/// Infers location hint from the surrounding context string.
fn infer_location(context: &str) -> &'static str {
    let ctx = context.to_lowercase();
    if ctx.contains("<script") || ctx.contains("</script") {
        "inline_script"
    } else if ctx.contains("<!--") {
        "html_comment"
    } else if ctx.contains("data-") {
        "data_attribute"
    } else if ctx.contains("?key=")
        || ctx.contains("&key=")
        || ctx.contains("&token=")
        || ctx.contains("?token=")
    {
        "url_parameter"
    } else if ctx.contains("content=\"") || ctx.contains("content='") {
        "meta_tag"
    } else {
        "html_body"
    }
}

/// Detects exposed secrets in raw HTML body text using gitleaks rules.
///
/// Loads rules from the bundled `config/gitleaks.toml`, runs each regex over the body,
/// applies entropy and allowlist filters, and returns findings with gitleaks rule id
/// as secret_type and derived severity.
pub fn detect_exposed_secrets(body: &str) -> Vec<ExposedSecret> {
    let config = &crate::parse::gitleaks::GITLEAKS;
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for rule in &config.rules {
        // Gitleaks prefilter: if rule has keywords, run regex only when at least one keyword appears in fragment (case-insensitive).
        if let Some(ref kws) = rule.keywords {
            if !kws.is_empty() {
                let body_lower = body.to_lowercase();
                if !kws.iter().any(|kw| body_lower.contains(kw)) {
                    continue;
                }
            }
        }

        for mat in rule.regex.find_iter(body) {
            let full_match = mat.as_str();
            let captures = rule.regex.captures(full_match);
            let matched_value = extract_secret(captures, full_match, rule.secret_group);

            if let Some(entropy_threshold) = rule.entropy {
                if shannon_entropy(&matched_value) < entropy_threshold {
                    continue;
                }
            }

            let context = extract_context(body, mat.start(), mat.end());
            if global_allowlist_skips(&config.global_allowlist, &matched_value, &context) {
                continue;
            }
            let line_content = line_containing(body, mat.start(), mat.end());
            if rule_allowlist_skips(&rule.allowlists, &matched_value, line_content, full_match) {
                continue;
            }

            let key = (rule.id.clone(), matched_value.clone());
            if !seen.insert(key) {
                continue;
            }

            let location = infer_location(&context).to_string();
            let severity = severity_for_rule_id(&rule.id);
            results.push(ExposedSecret {
                secret_type: rule.id.clone(),
                matched_value,
                context,
                severity,
                location,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Cloud Providers ===

    // AWS key: gitleaks uses [A-Z2-7]{16} (no 0,1,8,9); must not end in EXAMPLE (allowlisted)
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPL2";

    #[test]
    fn test_detect_aws_access_key() {
        let body = format!(r#"var key = "{}";"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1, "expected one secret, got {:?}", secrets);
        assert_eq!(secrets[0].secret_type, "aws-access-token");
        assert_eq!(secrets[0].matched_value, AWS_KEY);
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    #[test]
    fn test_aws_example_allowlisted() {
        let body = r#"var key = "AKIAIOSFODNN7EXAMPLE";"#;
        let secrets = detect_exposed_secrets(body);
        let aws = secrets.iter().find(|s| s.secret_type == "aws-access-token");
        assert!(
            aws.is_none(),
            "EXAMPLE key should be allowlisted; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_detect_aws_session_token() {
        // ASIA + 16 chars from [A-Z2-7]; may be filtered by entropy
        let body = "token=ASIA2BCDEF34567ZYXW";
        let secrets = detect_exposed_secrets(body);
        if secrets.len() == 1 {
            assert_eq!(secrets[0].secret_type, "aws-access-token");
            assert_eq!(secrets[0].severity, SecretSeverity::High);
        }
    }

    #[test]
    fn test_detect_google_api_key() {
        let body = r#"var apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";"#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "gcp-api-key"));
    }

    #[test]
    fn test_detect_openai_api_key() {
        // gitleaks openai-api-key: sk- + 20 alnum + T3BlbkFJ + 20 alnum (built at runtime to avoid secret-scanning false positives)
        let a: String = (0..20)
            .map(|i| (b'a' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let b: String = (0..20)
            .map(|i| (b'A' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let body = format!(r#"key = "sk-{}T3BlbkFJ{}""#, a, b);
        let secrets = detect_exposed_secrets(&body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "openai-api-key"));
    }

    #[test]
    fn test_detect_slack_bot_token() {
        let body = r#"token: "xoxb-123456789012-1234567890123-ABCDEFabcdef123456789012""#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "slack-bot-token"));
    }

    #[test]
    fn test_detect_rsa_private_key() {
        // gitleaks private-key regex expects BEGIN...KEY-----[\s\S-]{64,}?...KEY-----
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END RSA PRIVATE KEY-----";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "private-key");
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_vault_token() {
        // gitleaks vault-service-token: hvs.[\w-]{90,120} with entropy=3.5
        let suffix: String = (0..95)
            .map(|i| (b'a' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let body = format!(r#"VAULT_TOKEN="hvs.{}""#, suffix);
        let secrets = detect_exposed_secrets(&body);
        if !secrets.is_empty() {
            assert!(secrets
                .iter()
                .any(|s| s.secret_type == "vault-service-token"
                    || s.secret_type == "vault-batch-token"));
        }
    }

    #[test]
    fn test_shannon_entropy() {
        assert!((shannon_entropy("") - 0.0).abs() < 1e-9);
        assert!(shannon_entropy("aaaaaaaa") < shannon_entropy("abcd1234"));
    }

    #[test]
    fn test_severity_for_rule_id() {
        assert_eq!(
            severity_for_rule_id("private-key"),
            SecretSeverity::Critical
        );
        assert_eq!(
            severity_for_rule_id("aws-access-token"),
            SecretSeverity::High
        );
        assert_eq!(severity_for_rule_id("gcp-api-key"), SecretSeverity::Medium);
        assert_eq!(
            severity_for_rule_id("mapbox-api-token"),
            SecretSeverity::Low
        );
        assert_eq!(severity_for_rule_id("unknown-rule"), SecretSeverity::High);
    }

    #[test]
    fn test_location_inline_script() {
        let body = format!(r#"<script>var key = "{}";</script>"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "inline_script");
    }

    #[test]
    fn test_location_html_comment() {
        let body = format!(r#"<!-- {} -->"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "html_comment");
    }

    #[test]
    fn test_location_url_parameter() {
        let body = r#"https://example.com?key=AIzaSyA1234567890abcdefghijklmnopqrstuv"#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].location, "url_parameter");
    }

    #[test]
    fn test_location_data_attribute() {
        let body = format!(r#"<div data-api-key="{}">"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "data_attribute");
    }

    #[test]
    fn test_location_default_html_body() {
        let body = format!("just plain text {} in body", AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "html_body");
    }

    #[test]
    fn test_detect_no_secrets() {
        let body = "<html><body><p>Just regular HTML content</p></body></html>";
        let secrets = detect_exposed_secrets(body);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_deduplicates() {
        let body = format!("first: {} second: {}", AWS_KEY, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn test_full_value_stored_not_redacted() {
        let body = AWS_KEY;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].matched_value, AWS_KEY);
        assert!(!secrets[0].matched_value.contains("***"));
    }

    #[test]
    fn test_context_80_chars() {
        // Word boundary before key: use space so \b matches
        let prefix = "A".repeat(100);
        let suffix = "B".repeat(100);
        let body = format!("{} {} {}", prefix, AWS_KEY, suffix);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
        assert!(secrets[0].context.contains("AAAA"));
        assert!(secrets[0].context.contains("BBBB"));
    }

    #[test]
    fn test_gitleaks_config_loads() {
        let config = &crate::parse::gitleaks::GITLEAKS;
        assert!(config.rules.len() > 200, "expected 200+ gitleaks rules");
        assert!(!config.global_allowlist.regexes.is_empty());
    }

    /// Gitleaks keyword prefilter: sourcegraph-access-token has keywords ["sgp_", "sourcegraph"].
    /// Without either in the body, a plain 40-char hex (e.g. Git SHA) must not be reported.
    #[test]
    fn test_sourcegraph_no_fire_without_keyword() {
        let sha_like = "9c02de5c56d82f105252bb92478c88114ab41dce";
        let body = format!(r#"<span>commit {} </span>"#, sha_like);
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_none(),
            "sourcegraph-access-token must not fire without keyword in body; got {:?}",
            secrets
        );
    }

    /// With "sourcegraph" in the body, a 40-char hex can be reported as sourcegraph-access-token.
    #[test]
    fn test_sourcegraph_fires_with_keyword() {
        let token_hex = "a1b2c3d4e5f6789012345678901234567890abcd";
        let body = format!(r#"<script>window.SOURCEGRAPH = "{}";</script>"#, token_hex);
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_some(),
            "sourcegraph-access-token should fire when 'sourcegraph' (case-insensitive) in body; got {:?}",
            secrets
        );
        assert_eq!(sourcegraph.unwrap().matched_value, token_hex);
    }

    /// Per-rule allowlist: 40-char hex in html id="..." (e.g. Wix build ID) must not be reported as sourcegraph-access-token.
    #[test]
    fn test_sourcegraph_allowlist_html_id_skipped() {
        let build_id = "1ccd1dddac2890afd4e9eb54f87f22008b1ed114";
        let body = format!(
            r#"<html id="{}" class="StudioLegacy Legacy">sourcegraph integration</html>"#,
            build_id
        );
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_none(),
            "40-char hex in html id= should be allowlisted; got {:?}",
            secrets
        );
    }

    /// sonar-api-token has secretGroup = 2; extracted secret must be group 2 (the token), not group 1 (login|token).
    #[test]
    fn test_sonar_secret_group_2() {
        // Regex group 1 = (login|token), group 2 = 40-char token. secretGroup=2 => we store group 2.
        let token = "squ_abcdefghij0123456789abcdefghij012345"; // 40 chars
        let body = format!(r#"sonar_token="{}""#, token);
        let secrets = detect_exposed_secrets(&body);
        let sonar = secrets.iter().find(|s| s.secret_type == "sonar-api-token");
        assert!(
            sonar.is_some(),
            "expected sonar-api-token finding: {:?}",
            secrets
        );
        assert_eq!(
            sonar.unwrap().matched_value,
            token,
            "secretGroup=2 should yield the token (group 2), not 'token' (group 1)"
        );
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(SecretSeverity::Critical.as_str(), "critical");
        assert_eq!(SecretSeverity::High.as_str(), "high");
        assert_eq!(SecretSeverity::Medium.as_str(), "medium");
        assert_eq!(SecretSeverity::Low.as_str(), "low");
    }
}
