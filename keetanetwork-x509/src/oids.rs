//! Object Identifiers (OIDs) for X.509 certificates.
//!
//! This module defines commonly used OIDs for X.509 certificates.

// Algorithm identifiers
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_WITH_SHA3_256: &str = "2.16.840.1.101.3.4.3.10";

// Hash algorithm identifiers
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const SHA3_256: &str = "2.16.840.1.101.3.4.2.8";

// Elliptic curve identifiers
pub const SECP256R1: &str = "1.2.840.10045.3.1.7";
pub const SECP256K1: &str = "1.3.132.0.10";

// EdDSA identifiers
pub const ED25519: &str = "1.3.101.112";

// Common Name
pub const CN: &str = "2.5.4.3";
// Organization
pub const O: &str = "2.5.4.10";
// Organizational Unit
pub const OU: &str = "2.5.4.11";
// Country
pub const C: &str = "2.5.4.6";
// State or Province
pub const ST: &str = "2.5.4.8";
// Locality
pub const L: &str = "2.5.4.7";
// Email Address (PKCS #9)
pub const EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1";

// Extensions
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const KEY_USAGE: &str = "2.5.29.15";
pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
pub const CERTIFICATE_POLICIES: &str = "2.5.29.32";
pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
pub const POLICY_MAPPINGS: &str = "2.5.29.33";
pub const POLICY_CONSTRAINTS: &str = "2.5.29.36";
pub const ISSUER_ALT_NAME: &str = "2.5.29.18";
pub const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";

// Extended Key Usage identifiers
pub const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
pub const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
pub const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
pub const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
pub const OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
