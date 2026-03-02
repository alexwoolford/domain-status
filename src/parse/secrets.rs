//! Exposed secret detection in HTML content.
//!
//! Scans HTML body text for accidentally exposed secrets and credentials
//! using ~55 high-confidence regex patterns across cloud providers, AI/ML,
//! payment, communication, source control, databases, infrastructure, and more.
//!
//! Inspired by gitleaks and truffleHog — focused on patterns with distinctive
//! prefixes to minimize false positives on public web pages.
//!
//! Each finding includes:
//! - **severity**: critical / high / medium / low (static per secret type)
//! - **location**: heuristic for where in the HTML the secret was found
//! - **context**: ~80 chars before + match + ~80 chars after for analyst triage

use regex::Regex;
use std::fmt;
use std::sync::LazyLock;

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

/// Types of secrets that can be detected.
///
/// Organized by category. Each variant maps to a snake_case string for DB storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub secret_type: SecretType,
    /// Full matched value as found on the public page.
    pub matched_value: String,
    /// Surrounding text for context (~80 chars before + match + ~80 chars after).
    pub context: String,
    /// Severity classification (critical / high / medium / low).
    pub severity: SecretSeverity,
    /// Heuristic location hint (inline_script, html_comment, url_parameter, etc.).
    pub location: String,
}

/// A compiled secret detection pattern.
struct CompiledPattern {
    regex: Regex,
    secret_type: SecretType,
}

/// All secret detection patterns, compiled once at first use.
///
/// Patterns are ordered so that more specific patterns come before broader ones
/// (e.g., `sk-ant-` before generic `sk-` patterns, `sk-proj-` before `sk-`).
static PATTERNS: LazyLock<Vec<CompiledPattern>> = LazyLock::new(|| {
    let raw: &[(&str, SecretType)] = &[
        // === Cloud Providers ===
        (r"AKIA[0-9A-Z]{16}", SecretType::AwsAccessKey),
        // AWS session token (temporary credentials — more urgent than AKIA)
        (r"ASIA[0-9A-Z]{16}", SecretType::AwsSessionToken),
        (
            r#"(?i)aws.{0,30}['"][0-9a-zA-Z/+]{40}['"]"#,
            SecretType::AwsSecretKey,
        ),
        (r"AIza[0-9A-Za-z\-_]{35}", SecretType::GoogleApiKey),
        (r"ya29\.[0-9A-Za-z\-_]{20,}", SecretType::GoogleOAuthToken),
        (
            r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]+",
            SecretType::AzureConnectionString,
        ),
        (
            r"(?i)sig=[A-Za-z0-9%/+=]{20,}&se=\d+",
            SecretType::AzureSasToken,
        ),
        // === AI/ML Providers ===
        // Anthropic must come before OpenAI legacy to avoid sk- overlap
        (r"sk-ant-[A-Za-z0-9_-]{20,}", SecretType::AnthropicApiKey),
        (r"sk-proj-[A-Za-z0-9_-]{20,}", SecretType::OpenAiApiKey),
        (r"sk-[A-Za-z0-9]{48,}", SecretType::OpenAiApiKey),
        (r"hf_[A-Za-z0-9]{20,}", SecretType::HuggingFaceToken),
        // === Payment ===
        (
            r"pk_live_[0-9a-zA-Z]{24,}",
            SecretType::StripePublishableKey,
        ),
        (r"sk_live_[0-9a-zA-Z]{24,}", SecretType::StripeSecretKey),
        (r"rk_live_[0-9a-zA-Z]{24,}", SecretType::StripeRestrictedKey),
        (
            r"sq0(?:atp|csp)-[A-Za-z0-9_-]{22,}",
            SecretType::SquareAccessToken,
        ),
        // === Communication ===
        (
            r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
            SecretType::SlackWebhook,
        ),
        (
            r"xoxb-[0-9]+-[0-9A-Za-z]+-[A-Za-z0-9]+",
            SecretType::SlackBotToken,
        ),
        (
            r"xapp-[0-9]+-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+",
            SecretType::SlackAppToken,
        ),
        (
            r"xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+",
            SecretType::SlackUserToken,
        ),
        (
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            SecretType::DiscordWebhook,
        ),
        (
            r"[MN][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
            SecretType::DiscordBotToken,
        ),
        (r"AC[a-f0-9]{32}", SecretType::TwilioAccountSid),
        (
            r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
            SecretType::SendGridApiKey,
        ),
        // === Source Control ===
        (
            r"github_pat_[A-Za-z0-9_]{22,}",
            SecretType::GitHubFineGrained,
        ),
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", SecretType::GitHubToken),
        (r"glpat-[A-Za-z0-9_-]{20,}", SecretType::GitLabToken),
        (r"ATBB[A-Za-z0-9]{24,}", SecretType::BitbucketAppPassword),
        // === Database ===
        (
            r#"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^\s'"<>]{10,}"#,
            SecretType::DatabaseUrl,
        ),
        (
            r"https://[a-z0-9-]+\.firebaseio\.com",
            SecretType::FirebaseUrl,
        ),
        (
            r"AccountEndpoint=https://[^;]+;AccountKey=[A-Za-z0-9/+=]+",
            SecretType::AzureCosmosDb,
        ),
        // === Cryptographic Keys ===
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            SecretType::PrivateKey,
        ),
        // === Infrastructure ===
        (
            r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            SecretType::HerokuApiKey,
        ),
        (r"ver_[A-Za-z0-9_-]{24,}", SecretType::VercelToken),
        (r"dop_v1_[a-f0-9]{64}", SecretType::DigitalOceanToken),
        (r"npm_[A-Za-z0-9]{36,}", SecretType::NpmToken),
        (r"pypi-AgE[A-Za-z0-9_-]{20,}", SecretType::PypiToken),
        // Terraform Cloud token (atlasv1 format)
        (
            r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}",
            SecretType::TerraformCloudToken,
        ),
        // HashiCorp Vault token
        (r"hvs\.[A-Za-z0-9_-]{24,}", SecretType::VaultToken),
        // Fly.io token
        (r"fo1_[A-Za-z0-9_-]{39,}", SecretType::FlyIoToken),
        // === Services ===
        (r"[a-f0-9]{32}-us\d{1,2}", SecretType::MailchimpApiKey),
        (r"key-[a-f0-9]{32}", SecretType::MailgunApiKey),
        (
            r"(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            SecretType::MapboxToken,
        ),
        (
            r"shp(?:at|pa|tk)_[a-fA-F0-9]{32,}",
            SecretType::ShopifyToken,
        ),
        (
            r#"(?i)algolia.{0,20}['"][a-f0-9]{32}['"]"#,
            SecretType::AlgoliaApiKey,
        ),
        // Sentry DSN (client key embedded in ingest URL)
        (
            r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+",
            SecretType::SentryDsn,
        ),
        // Plaid tokens (access/public/transfer with environment prefix)
        (
            r"(?:access|public|transfer)-(?:sandbox|development|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            SecretType::PlaidToken,
        ),
        // Supabase service key
        (r"sbp_[a-f0-9]{40}", SecretType::SupabaseKey),
        // === Monitoring ===
        (
            r#"(?i)datadog.{0,20}['"][a-f0-9]{32}['"]"#,
            SecretType::DatadogApiKey,
        ),
        (r"NRAK-[A-Z0-9]{27}", SecretType::NewRelicKey),
        // Grafana cloud/service account tokens
        (r"glc_[A-Za-z0-9+/]{32,}={0,2}", SecretType::GrafanaToken),
        (
            r"glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}",
            SecretType::GrafanaToken,
        ),
        // === Additional Infrastructure ===
        // Cloudflare API token (v1.0 format)
        (
            r"v1\.0-[a-f0-9]{24}-[a-f0-9]{146}",
            SecretType::CloudflareApiToken,
        ),
        // Linear API key
        (r"lin_api_[A-Za-z0-9]{40}", SecretType::LinearApiKey),
        // Doppler service token
        (
            r"dp\.st\.[a-z0-9_-]+\.[A-Za-z0-9]{40,}",
            SecretType::DopplerToken,
        ),
        // Fastly API token
        (
            r#"(?i)fastly.{0,20}['"][A-Za-z0-9_-]{32,}['"]"#,
            SecretType::FastlyApiToken,
        ),
    ];

    raw.iter()
        .map(|(pattern, secret_type)| CompiledPattern {
            regex: Regex::new(pattern)
                .unwrap_or_else(|e| panic!("Invalid secret pattern for {}: {}", secret_type, e)),
            secret_type: *secret_type,
        })
        .collect()
});

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

/// Returns true if a matched value for VercelToken looks like an identifier (CSS/JS
/// class or variable name) rather than a real token, to avoid false positives.
fn vercel_token_likely_identifier(matched_value: &str) -> bool {
    let suffix = match matched_value.strip_prefix("ver_") {
        Some(s) => s,
        None => return false,
    };
    let underscore_count = suffix.chars().filter(|c| *c == '_').count();
    let has_hyphen = suffix.contains('-');
    // Real tokens are typically one alphanumeric block; identifiers have multiple
    // underscores (e.g. ver_effect_offset_hover_popover) or hyphens (e.g. ver_CTA-webimage-...).
    underscore_count >= 2 || has_hyphen
}

/// Detects exposed secrets in raw HTML body text.
///
/// Scans the body for ~55 known secret patterns across cloud providers, AI/ML,
/// payment, communication, source control, databases, infrastructure, and more.
///
/// Full matched values are stored (no redaction) since these are already on the
/// public web. Each finding includes severity and location metadata.
pub fn detect_exposed_secrets(body: &str) -> Vec<ExposedSecret> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for pattern in PATTERNS.iter() {
        for mat in pattern.regex.find_iter(body) {
            let matched_value = mat.as_str().to_string();

            if pattern.secret_type == SecretType::VercelToken
                && vercel_token_likely_identifier(&matched_value)
            {
                continue;
            }

            let key = (pattern.secret_type, matched_value.clone());

            if seen.insert(key) {
                let context = extract_context(body, mat.start(), mat.end());
                let location = infer_location(&context).to_string();
                let severity = pattern.secret_type.severity();
                results.push(ExposedSecret {
                    secret_type: pattern.secret_type,
                    matched_value,
                    context,
                    severity,
                    location,
                });
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Cloud Providers ===

    #[test]
    fn test_detect_aws_access_key() {
        let body = r#"var key = "AKIAIOSFODNN7EXAMPLE";"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AwsAccessKey);
        assert_eq!(secrets[0].matched_value, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_aws_session_token() {
        let body = "ASIATEMP1234567890AB";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AwsSessionToken);
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_aws_secret_key() {
        let body = r#"aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AwsSecretKey);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_google_api_key() {
        let body = r#"var apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GoogleApiKey);
        assert_eq!(secrets[0].severity, SecretSeverity::Medium);
    }

    #[test]
    fn test_detect_google_oauth_token() {
        let body = r#"access_token: "ya29.a0AfH6SMBQ_example_token_value_here""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GoogleOAuthToken);
    }

    #[test]
    fn test_detect_azure_connection_string() {
        let body = "DefaultEndpointsProtocol=https;AccountName=myacct;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567890ABCDEFGHIJKLMN==";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AzureConnectionString);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    // === AI/ML Providers ===

    #[test]
    fn test_detect_openai_project_key() {
        let body = r#"const key = "sk-proj-abcdef1234567890ABCDEF";"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::OpenAiApiKey);
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_anthropic_api_key() {
        let body = r#"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AnthropicApiKey);
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_huggingface_token() {
        let body = r#"HF_TOKEN="hf_abcdefghijklmnopqrstuvwxyz""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::HuggingFaceToken);
    }

    // === Payment ===

    #[test]
    fn test_detect_stripe_publishable_key() {
        let body = r#"Stripe.setPublishableKey('pk_live_abcdefghijklmnopqrstuvwx');"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::StripePublishableKey);
        assert_eq!(secrets[0].severity, SecretSeverity::Low);
    }

    #[test]
    fn test_detect_stripe_secret_key() {
        let body = r#"const key = "sk_live_abcdefghijklmnopqrstuvwx";"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::StripeSecretKey);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    // === Communication ===

    #[test]
    fn test_detect_slack_webhook() {
        let body = r#"url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::SlackWebhook);
        assert_eq!(secrets[0].severity, SecretSeverity::Medium);
    }

    #[test]
    fn test_detect_slack_bot_token() {
        let body = r#"token: "xoxb-123456789012-1234567890123-ABCDEFabcdef123456789012""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::SlackBotToken);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_discord_webhook() {
        let body = "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz-ABCDEFG";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::DiscordWebhook);
    }

    #[test]
    fn test_detect_sendgrid_api_key() {
        let body =
            r#"key = "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::SendGridApiKey);
        assert_eq!(secrets[0].severity, SecretSeverity::High);
    }

    // === Source Control ===

    #[test]
    fn test_detect_github_token() {
        let body = r#"token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GitHubToken);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_github_fine_grained() {
        let body = r#"token = "github_pat_11AAAAAA0abcdef1234567890ABCDEF""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GitHubFineGrained);
    }

    #[test]
    fn test_detect_gitlab_token() {
        let body = r#"GITLAB_TOKEN="glpat-abcdefghijklmnopqrst""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GitLabToken);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    // === Database ===

    #[test]
    fn test_detect_database_url_postgres() {
        let body = r#"DATABASE_URL=postgres://user:pass@host:5432/mydb"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::DatabaseUrl);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_database_url_redis() {
        let body = r#"redis://default:secretpassword@redis-host:6379/0"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::DatabaseUrl);
    }

    #[test]
    fn test_detect_firebase_url() {
        let body = r#"var config = { databaseURL: "https://my-app-123.firebaseio.com" };"#;
        let secrets: Vec<_> = detect_exposed_secrets(body)
            .into_iter()
            .filter(|s| s.secret_type == SecretType::FirebaseUrl)
            .collect();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].severity, SecretSeverity::Low);
    }

    #[test]
    fn test_detect_sentry_dsn() {
        let body = r#"Sentry.init({ dsn: "https://abc123def456abc123def456abc12345@o12345.ingest.sentry.io/6789012" });"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::SentryDsn);
        assert_eq!(secrets[0].severity, SecretSeverity::Medium);
    }

    // === Cryptographic Keys ===

    #[test]
    fn test_detect_rsa_private_key() {
        let body = "-----BEGIN RSA PRIVATE KEY-----";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::PrivateKey);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_openssh_private_key() {
        let body = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::PrivateKey);
    }

    // === New Infrastructure Patterns ===

    #[test]
    fn test_detect_vault_token() {
        let body = r#"VAULT_TOKEN="hvs.CAESIK_example_token_value_here""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::VaultToken);
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_vercel_token() {
        let body = r#"VERCEL_TOKEN="ver_abcdefghijklmnopqrstuvwxyz""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::VercelToken);
    }

    #[test]
    fn test_vercel_token_identifier_false_positives_filtered() {
        // CSS/JS identifiers with ver_ prefix and multiple underscores or hyphens must not be reported.
        let body = r#"<div class="ver_effect_offset_hover_popover ver__section-video-container">"#;
        let secrets: Vec<_> = detect_exposed_secrets(body)
            .into_iter()
            .filter(|s| s.secret_type == SecretType::VercelToken)
            .collect();
        assert!(
            secrets.is_empty(),
            "identifier-like ver_ strings should not be reported as VercelToken; got {:?}",
            secrets
                .iter()
                .map(|s| s.matched_value.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detect_npm_token() {
        let body = r#"//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::NpmToken);
    }

    #[test]
    fn test_detect_grafana_cloud_token() {
        let body = r#"token = "glc_abcdefghijklmnopqrstuvwxyz012345==""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::GrafanaToken);
    }

    #[test]
    fn test_detect_new_relic_key() {
        let body = r#"NEW_RELIC_KEY="NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::NewRelicKey);
    }

    #[test]
    fn test_detect_linear_api_key() {
        let body = r#"LINEAR_API_KEY="lin_api_abcdefghijklmnopqrstuvwxyz0123456789ABCD""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::LinearApiKey);
    }

    #[test]
    fn test_detect_supabase_key() {
        let body = r#"SUPABASE_KEY="sbp_abcdef1234567890abcdef1234567890abcdef12""#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::SupabaseKey);
    }

    // === Severity ===

    #[test]
    fn test_severity_classification() {
        assert_eq!(
            SecretType::AwsSecretKey.severity(),
            SecretSeverity::Critical
        );
        assert_eq!(SecretType::PrivateKey.severity(), SecretSeverity::Critical);
        assert_eq!(SecretType::DatabaseUrl.severity(), SecretSeverity::Critical);
        assert_eq!(SecretType::AwsAccessKey.severity(), SecretSeverity::High);
        assert_eq!(SecretType::OpenAiApiKey.severity(), SecretSeverity::High);
        assert_eq!(SecretType::GoogleApiKey.severity(), SecretSeverity::Medium);
        assert_eq!(SecretType::SlackWebhook.severity(), SecretSeverity::Medium);
        assert_eq!(
            SecretType::StripePublishableKey.severity(),
            SecretSeverity::Low
        );
        assert_eq!(SecretType::FirebaseUrl.severity(), SecretSeverity::Low);
    }

    // === Location Heuristic ===

    #[test]
    fn test_location_inline_script() {
        let body = r#"<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].location, "inline_script");
    }

    #[test]
    fn test_location_html_comment() {
        let body = r#"<!-- AKIAIOSFODNN7EXAMPLE -->"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].location, "html_comment");
    }

    #[test]
    fn test_location_url_parameter() {
        let body = r#"https://example.com?key=AIzaSyA1234567890abcdefghijklmnopqrstuv"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].location, "url_parameter");
    }

    #[test]
    fn test_location_data_attribute() {
        let body = r#"<div data-api-key="AKIAIOSFODNN7EXAMPLE">"#;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].location, "data_attribute");
    }

    #[test]
    fn test_location_default_html_body() {
        let body = "just plain text AKIAIOSFODNN7EXAMPLE in body";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].location, "html_body");
    }

    // === General behavior ===

    #[test]
    fn test_detect_no_secrets() {
        let body = "<html><body><p>Just regular HTML content</p></body></html>";
        let secrets = detect_exposed_secrets(body);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_multiple_secrets() {
        let body = r#"
            var aws = "AKIAIOSFODNN7EXAMPLE";
            var google = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
            var slack = "xoxb-123456789012-1234567890123-ABCDEFabcdef123456789012";
        "#;
        let secrets = detect_exposed_secrets(body);
        assert!(secrets.len() >= 3);
    }

    #[test]
    fn test_detect_deduplicates() {
        let body = "first: AKIAIOSFODNN7EXAMPLE second: AKIAIOSFODNN7EXAMPLE";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn test_full_value_stored_not_redacted() {
        let body = "AKIAIOSFODNN7EXAMPLE";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].matched_value, "AKIAIOSFODNN7EXAMPLE");
        assert!(!secrets[0].matched_value.contains("***"));
    }

    #[test]
    fn test_context_80_chars() {
        // Verify the wider 80-char context window
        let prefix = "A".repeat(100);
        let suffix = "B".repeat(100);
        let body = format!("{}AKIAIOSFODNN7EXAMPLE{}", prefix, suffix);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
        // Context should contain ~80 chars before the match
        assert!(secrets[0].context.contains("AAAA"));
        assert!(secrets[0].context.contains("BBBB"));
    }

    #[test]
    fn test_anthropic_key_not_matched_as_openai() {
        let body = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::AnthropicApiKey);
    }

    #[test]
    fn test_stripe_key_not_matched_as_openai() {
        let body = "sk_live_abcdefghijklmnopqrstuvwx";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, SecretType::StripeSecretKey);
    }

    #[test]
    fn test_no_jwt_pattern() {
        // JWT pattern was removed — too much noise from OAuth state tokens
        let body = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let secrets = detect_exposed_secrets(body);
        assert!(
            secrets.is_empty(),
            "JWT tokens should not be detected — too noisy"
        );
    }

    #[test]
    fn test_secret_type_as_str() {
        assert_eq!(SecretType::AwsAccessKey.as_str(), "aws_access_key");
        assert_eq!(SecretType::OpenAiApiKey.as_str(), "openai_api_key");
        assert_eq!(SecretType::VaultToken.as_str(), "vault_token");
        assert_eq!(SecretType::SentryDsn.as_str(), "sentry_dsn");
        assert_eq!(SecretType::GrafanaToken.as_str(), "grafana_token");
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(SecretSeverity::Critical.as_str(), "critical");
        assert_eq!(SecretSeverity::High.as_str(), "high");
        assert_eq!(SecretSeverity::Medium.as_str(), "medium");
        assert_eq!(SecretSeverity::Low.as_str(), "low");
    }
}
