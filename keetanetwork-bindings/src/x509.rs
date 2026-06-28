//! X.509 logic shared across binding boundaries: certificate-error reduction,
//! per-key-type dispatch for subject keys and signing, and the offline base
//! certificate primitive operations.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use keetanetwork_account::GenericAccount;
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::error::CertificateError;

use crate::error::CodedError;

/// Code for an account whose key type cannot sign or certify.
const UNSUPPORTED_KEY_TYPE: &str = "UNSUPPORTED_KEY_TYPE";

/// Code for a timestamp outside the representable range.
const INVALID_DATE: &str = "INVALID_DATE";

impl From<CertificateError> for CodedError {
	fn from(error: CertificateError) -> Self {
		let code = match error {
			CertificateError::InvalidCertificate => "INVALID_CERTIFICATE",
			CertificateError::ValidationFailed { .. } => "VALIDATION_FAILED",
			CertificateError::Expired => "CERTIFICATE_EXPIRED",
			CertificateError::NotYetValid => "CERTIFICATE_NOT_YET_VALID",
			CertificateError::Asn1ParseError { .. } => "ASN1_PARSE_ERROR",
			CertificateError::MissingField { .. } => "MISSING_FIELD",
			CertificateError::InvalidExtension { .. } => "INVALID_EXTENSION",
			CertificateError::ChainValidationFailed { .. } => "CHAIN_VALIDATION_FAILED",
			CertificateError::UnsupportedVersion { .. } => "UNSUPPORTED_VERSION",
			CertificateError::CertificateSignatureVerificationFailed => "SIGNATURE_VERIFICATION_FAILED",
			CertificateError::CertificateDuplicateIncluded => "CERTIFICATE_DUPLICATE",
			CertificateError::CertificateOrphanFound => "CERTIFICATE_ORPHAN",
			CertificateError::CertificateCycleFound => "CERTIFICATE_CYCLE",
			CertificateError::CertificateInvalidGraphCount { .. } => "CERTIFICATE_INVALID_GRAPH_COUNT",
		};
		CodedError::new(code, error.to_string())
	}
}

/// Derive the subject public key info from a signing account, dispatching over
/// the concrete key type since the conversion is per-algorithm.
pub fn subject_public_key(account: &GenericAccount) -> Result<SubjectPublicKeyInfo, CodedError> {
	match account {
		GenericAccount::Ed25519(inner) => SubjectPublicKeyInfo::try_from(inner),
		GenericAccount::EcdsaSecp256k1(inner) => SubjectPublicKeyInfo::try_from(inner),
		GenericAccount::EcdsaSecp256r1(inner) => SubjectPublicKeyInfo::try_from(inner),
		_ => return Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "certificate subject key requires a signing account")),
	}
	.map_err(|error| CodedError::new("PUBLIC_KEY", error.as_ref()))
}

/// Sign `builder` with a signing account, dispatching over the concrete key
/// type since signing is per-algorithm.
pub fn build_signed(builder: &CertificateBuilder, account: &GenericAccount) -> Result<Certificate, CodedError> {
	match account {
		GenericAccount::Ed25519(inner) => builder.build(inner),
		GenericAccount::EcdsaSecp256k1(inner) => builder.build(inner),
		GenericAccount::EcdsaSecp256r1(inner) => builder.build(inner),
		_ => return Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "certificate signing requires a signing account")),
	}
	.map_err(CodedError::from)
}

/// Parse a PEM-encoded X.509 `certificate`.
pub fn certificate_from_pem(certificate: &str) -> Result<Certificate, CodedError> {
	Certificate::from_str(certificate).map_err(CodedError::from)
}

/// Parse a DER-encoded X.509 `certificate`.
pub fn certificate_from_der(certificate: &[u8]) -> Result<Certificate, CodedError> {
	Certificate::try_from(certificate).map_err(CodedError::from)
}

/// The PEM encoding of `certificate`.
pub fn certificate_pem(certificate: &Certificate) -> Result<String, CodedError> {
	certificate.to_pem().map_err(CodedError::from)
}

/// The DER encoding of `certificate`.
pub fn certificate_der(certificate: &Certificate) -> Result<Vec<u8>, CodedError> {
	certificate.to_der().map_err(CodedError::from)
}

/// Whether `certificate` is within its validity window at `unix_millis`.
pub fn certificate_valid_at(certificate: &Certificate, unix_millis: i64) -> Result<bool, CodedError> {
	let moment = DateTime::<Utc>::from_timestamp_millis(unix_millis)
		.ok_or_else(|| CodedError::new(INVALID_DATE, "unix milliseconds out of range"))?;
	certificate.is_valid_at(moment).map_err(CodedError::from)
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use keetanetwork_x509::doc_utils::create_test_certificate;

	use super::*;

	fn now_millis() -> i64 {
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system clock must be after the unix epoch")
			.as_millis() as i64
	}

	#[test]
	fn maps_expired_to_a_stable_code() {
		let coded = CodedError::from(CertificateError::Expired);
		assert_eq!(coded.code, "CERTIFICATE_EXPIRED");
	}

	#[test]
	fn maps_invalid_certificate_to_a_stable_code() {
		let coded = CodedError::from(CertificateError::InvalidCertificate);
		assert_eq!(coded.code, "INVALID_CERTIFICATE");
	}

	#[test]
	fn certificate_round_trips_through_pem_and_der() {
		let certificate = create_test_certificate("Test CA", None);
		let pem = certificate_pem(&certificate).expect("pem encoding must succeed");
		let parsed = certificate_from_pem(&pem).expect("pem must parse");

		let original_der = certificate_der(&certificate).expect("der must encode");
		let parsed_der = certificate_der(&parsed).expect("der must encode");
		assert_eq!(parsed_der, original_der);

		let reparsed = certificate_from_der(&parsed_der).expect("der must parse");
		assert_eq!(certificate_der(&reparsed).expect("der must encode"), original_der);
	}

	#[test]
	fn a_fresh_certificate_is_valid_now() {
		let certificate = create_test_certificate("Test CA", None);
		assert!(certificate_valid_at(&certificate, now_millis()).expect("validity check must succeed"));
	}

	#[test]
	fn malformed_pem_is_rejected_with_a_certificate_code() {
		let error = certificate_from_pem("not a certificate").expect_err("garbage must not parse");
		assert!(!error.code.is_empty());
	}

	#[test]
	fn a_timestamp_out_of_range_is_rejected() {
		let certificate = create_test_certificate("Test CA", None);
		let error = certificate_valid_at(&certificate, i64::MAX).expect_err("out-of-range moment must fail");
		assert_eq!(error.code, INVALID_DATE);
	}
}
