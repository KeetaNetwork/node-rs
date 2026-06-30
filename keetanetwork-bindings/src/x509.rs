//! X.509 logic shared across binding boundaries: certificate-error reduction,
//! per-key-type dispatch for subject keys and signing, and the base
//! certificate primitive operations.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use chrono::{DateTime, Utc};
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_x509::asn1::ObjectIdentifier;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::error::CertificateError;
use keetanetwork_x509::{oids, AlgorithmIdentifierOwned};
use num_bigint::BigUint;

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

/// The subject distinguished name of `certificate` as an RFC 4514 string.
pub fn certificate_subject(certificate: &Certificate) -> String {
	certificate.to_subject()
}

/// The issuer distinguished name of `certificate` as an RFC 4514 string.
pub fn certificate_issuer(certificate: &Certificate) -> String {
	certificate.to_issuer()
}

/// The serial number of `certificate` as a base-10 string, matching the
/// TypeScript `bigint` serial rather than a hex form.
pub fn certificate_serial(certificate: &Certificate) -> String {
	BigUint::from_bytes_be(certificate.to_serial_number().as_bytes()).to_str_radix(10)
}

/// The start of the validity window of `certificate` as Unix seconds.
pub fn certificate_not_before(certificate: &Certificate) -> i64 {
	certificate.to_not_before().timestamp()
}

/// The end of the validity window of `certificate` as Unix seconds.
pub fn certificate_not_after(certificate: &Certificate) -> i64 {
	certificate.to_not_after().timestamp()
}

/// The subject public key of `certificate` as a type-prefixed, hex-encoded key
/// identical to an account's `public_key`, so a caller can match a certificate's
/// subject to an account.
pub fn certificate_subject_public_key(certificate: &Certificate) -> Result<String, CodedError> {
	let spki = &certificate.tbs_certificate.subject_public_key_info;
	let key_type = subject_key_pair_type(&spki.algorithm)?;
	let raw = spki.subject_public_key.raw_bytes();

	let mut bytes = Vec::with_capacity(1 + raw.len());
	bytes.push(key_type as u8);
	bytes.extend_from_slice(raw);

	Ok(hex::encode(bytes))
}

/// Map a SubjectPublicKeyInfo algorithm (and, for ECDSA, its curve parameter) to
/// the Keeta key-pair type that prefixes a type-tagged key.
fn subject_key_pair_type(algorithm: &AlgorithmIdentifierOwned) -> Result<KeyPairType, CodedError> {
	let oid = algorithm.oid.to_string();

	if oid == oids::ED25519 {
		Ok(KeyPairType::ED25519)
	} else if oid == oids::SECP256K1 {
		Ok(KeyPairType::ECDSASECP256K1)
	} else if oid == oids::SECP256R1 {
		Ok(KeyPairType::ECDSASECP256R1)
	} else if oid == oids::EC_PUBLIC_KEY {
		subject_curve_key_pair_type(algorithm)
	} else {
		Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "unsupported certificate public-key algorithm"))
	}
}

/// Resolve the ECDSA curve carried in the algorithm parameters to its key-pair
/// type.
fn subject_curve_key_pair_type(algorithm: &AlgorithmIdentifierOwned) -> Result<KeyPairType, CodedError> {
	let curve = algorithm
		.parameters
		.as_ref()
		.ok_or_else(|| CodedError::new(UNSUPPORTED_KEY_TYPE, "ecdsa public key is missing a curve parameter"))?
		.decode_as::<ObjectIdentifier>()
		.map_err(|_| CodedError::new(UNSUPPORTED_KEY_TYPE, "unable to decode ecdsa curve parameter"))?
		.to_string();

	if curve == oids::SECP256K1 {
		Ok(KeyPairType::ECDSASECP256K1)
	} else if curve == oids::SECP256R1 {
		Ok(KeyPairType::ECDSASECP256R1)
	} else {
		Err(CodedError::new(UNSUPPORTED_KEY_TYPE, "unsupported ecdsa curve"))
	}
}

#[cfg(test)]
mod tests {
	use std::time::{SystemTime, UNIX_EPOCH};

	use keetanetwork_x509::doc_utils::{create_test_certificate, create_test_keys};
	use keetanetwork_x509::utils::create_dn;
	use keetanetwork_x509::SerialNumber;

	use super::*;
	use crate::account::{account_from_seed, account_public_key};

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

	#[test]
	fn reports_a_non_empty_subject_and_issuer() {
		let certificate = create_test_certificate("Test CA", None);
		assert!(!certificate_subject(&certificate).is_empty());
		assert!(!certificate_issuer(&certificate).is_empty());
	}

	#[test]
	fn reports_a_decimal_serial() {
		let certificate = create_test_certificate("Test CA", None);
		assert!(certificate_serial(&certificate)
			.chars()
			.all(|character| character.is_ascii_digit()));
	}

	#[test]
	fn orders_the_validity_window() {
		let certificate = create_test_certificate("Test CA", None);
		assert!(certificate_not_before(&certificate) < certificate_not_after(&certificate));
	}

	#[test]
	fn subject_public_key_matches_an_ed25519_account() {
		let (_, _, account) = create_test_keys(None);
		let certificate = create_test_certificate("Test CA", None);
		let expected = hex::encode(account.to_public_key_with_type());
		assert_eq!(certificate_subject_public_key(&certificate).unwrap(), expected);
	}

	#[test]
	fn subject_public_key_matches_a_secp256k1_account() {
		let subject = account_from_seed(&"11".repeat(32), 0, "ecdsa_secp256k1").unwrap();
		let issuer = account_from_seed(&"22".repeat(32), 0, "ecdsa_secp256k1").unwrap();
		let dn = create_dn(&[(oids::CN, "Subject")]).unwrap();
		let certificate = build_signed(
			&CertificateBuilder::new()
				.with_subject_public_key(subject_public_key(&subject).unwrap())
				.with_subject_dn(dn.clone())
				.with_issuer_dn(dn)
				.with_serial_number(SerialNumber::from(7u64))
				.with_validity_days(365),
			&issuer,
		)
		.unwrap();

		assert_eq!(certificate_subject_public_key(&certificate).unwrap(), account_public_key(&subject));
	}
}
