//! Object Identifiers (OIDs).
//!
//! This module defines commonly used OIDs for cryptographic algorithms.

// Algorithm identifiers (string format for backwards compatibility)
pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const ECDSA_WITH_SHA3_256: &str = "2.16.840.1.101.3.4.3.10";

// Elliptic curve identifiers (string format for backwards compatibility)
pub const SECP256R1: &str = "1.2.840.10045.3.1.7";
pub const SECP256K1: &str = "1.3.132.0.10";

// EdDSA identifiers (string format for backwards compatibility)
pub const ED25519: &str = "1.3.101.112";

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

// Distinguished Name attributes
pub const CN: &str = "2.5.4.3";
pub const O: &str = "2.5.4.10";
pub const OU: &str = "2.5.4.11";
pub const C: &str = "2.5.4.6";
pub const ST: &str = "2.5.4.8";
pub const L: &str = "2.5.4.7";
pub const EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1";

/// Typed OID constants for the `der` backend.
#[cfg(feature = "der")]
pub mod typed {
	use der::oid::ObjectIdentifier;

	/// NIST P-256 elliptic curve (secp256r1)
	pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
	/// Bitcoin elliptic curve (secp256k1)
	pub const SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
	/// Ed25519 signature algorithm
	pub const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
	/// EC Public Key algorithm identifier
	pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
	/// ECDSA with SHA-256 signature algorithm
	pub const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
}

// Build-script-generated `rasn`-typed OIDs.
#[cfg(all(feature = "rasn", not(feature = "der")))]
include!(concat!(env!("OUT_DIR"), "/generated/oids.rs"));
