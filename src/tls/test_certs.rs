//! Shared rcgen helpers for `src/tls` tests.

use rcgen::{
    date_time_ymd, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use std::net::IpAddr;

/// 2024-01-01T00:00:00Z (day-of-month 1; RFC 2822 `%d` padding trap).
pub(super) const DAY1_NOT_BEFORE_UNIX: i64 = 1_704_067_200;
/// 2025-01-09T00:00:00Z (day-of-month 9; same padding trap on `not_after`).
pub(super) const DAY9_NOT_AFTER_UNIX: i64 = 1_736_380_800;

/// CA/Browser Forum domain-validated policy (`2.23.140.1.2.1`) as a
/// `CertificatePolicies` SEQUENCE of one `PolicyInformation`.
const DV_POLICY_DER: &[u8] = &[
    0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01,
];

pub(super) const CUSTOM_EKU_OID: &str = "1.2.3.4.5";
pub(super) const DV_POLICY_OID: &str = "2.23.140.1.2.1";

pub(super) struct TestCert {
    pub der: Vec<u8>,
    pub key_der: Vec<u8>,
}

pub(super) struct TestCertOptions {
    pub dns_names: Vec<String>,
    pub ip_sans: Vec<IpAddr>,
    pub common_name: String,
    pub extra_eku: Option<Vec<u64>>,
    pub include_dv_policy: bool,
}

impl Default for TestCertOptions {
    fn default() -> Self {
        Self {
            dns_names: vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "*.example.com".to_string(),
            ],
            ip_sans: vec![IpAddr::from([192, 0, 2, 1])],
            common_name: "example.com".to_string(),
            extra_eku: Some(vec![1, 2, 3, 4, 5]),
            include_dv_policy: true,
        }
    }
}

pub(super) fn generate(options: TestCertOptions) -> TestCert {
    let mut names = options.dns_names;
    names.extend(options.ip_sans.iter().map(ToString::to_string));
    let mut params = CertificateParams::new(names).expect("certificate params");
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, options.common_name);
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::ExplicitNoCa;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2025, 1, 9);

    let mut ekus = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    if let Some(oid) = options.extra_eku {
        ekus.push(ExtendedKeyUsagePurpose::Other(oid));
    }
    params.extended_key_usages = ekus;

    if options.include_dv_policy {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 32],
                DV_POLICY_DER.to_vec(),
            ));
    }

    let key_pair = KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key_pair).expect("certificate");
    TestCert {
        der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
    }
}
