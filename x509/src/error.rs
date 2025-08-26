use snafu::Snafu;
use utils::{impl_error_from_with_fields, impl_variant_error_from};

/// Errors specific to X.509 certificate operations.
#[derive(Debug, Snafu, Clone, PartialEq)]
#[snafu(visibility(pub))]
pub enum CertificateError {
	/// Invalid certificate format
	#[snafu(display("Invalid certificate format"))]
	InvalidCertificate,
	/// Certificate validation failed
	#[snafu(display("Certificate validation failed: {reason}"))]
	ValidationFailed { reason: String },
	/// Certificate has expired
	#[snafu(display("Certificate has expired"))]
	Expired,
	/// Certificate is not yet valid
	#[snafu(display("Certificate is not yet valid"))]
	NotYetValid,
	/// ASN.1 parsing error
	#[snafu(display("ASN.1 parsing error: {message}"))]
	Asn1ParseError { message: String },
	/// Missing required field
	#[snafu(display("Missing required field: {field}"))]
	MissingField { field: String },
	/// Invalid extension
	#[snafu(display("Invalid extension: {oid}"))]
	InvalidExtension { oid: String },
	/// Certificate chain validation failed
	#[snafu(display("Certificate chain validation failed: {reason}"))]
	ChainValidationFailed { reason: String },
	/// Unsupported certificate version
	#[snafu(display("Unsupported certificate version: {version}"))]
	UnsupportedVersion { version: u32 },
	/// Certificate signature verification failed
	#[snafu(display("Certificate signature verification failed"))]
	CertificateSignatureVerificationFailed,
	/// Duplicate certificate included in set
	#[snafu(display("Duplicate certificate included in certificate set"))]
	CertificateDuplicateIncluded,
	/// Orphan certificate found with no path to root
	#[snafu(display("Orphan certificate found with no path to root"))]
	CertificateOrphanFound,
	/// Cycle detected in certificate chain
	#[snafu(display("Cycle detected in certificate chain"))]
	CertificateCycleFound,
}

// Use macros for simple variant mappings
impl_variant_error_from!(CertificateError, {
	der::oid::Error => InvalidCertificate,
	base64::DecodeError => InvalidCertificate,
	crypto::operations::SignatureError => CertificateSignatureVerificationFailed,
});

// Use macros for field transformations
impl_error_from_with_fields!(CertificateError, {
	der::Error => Asn1ParseError { message: |error: der::Error| format!("DER error: {error}") },
	crypto::error::CryptoError => Asn1ParseError { message: |error: crypto::error::CryptoError| format!("Crypto error: {error}") },
	asn1::error::Asn1Error => Asn1ParseError { message: |error: asn1::error::Asn1Error| format!("ASN.1 error: {error}") },
});

#[cfg(test)]
mod tests {
	use der::Decode;

	use super::*;
	use utils::{test_error_from_conversions, test_error_variants};

	test_error_variants! {
		test_all_error_variants, [
			CertificateError::InvalidCertificate,
			CertificateError::ValidationFailed { reason: "test".to_string() },
			CertificateError::Expired,
			CertificateError::NotYetValid,
			CertificateError::Asn1ParseError { message: "test".to_string() },
			CertificateError::MissingField { field: "test".to_string() },
			CertificateError::InvalidExtension { oid: "test".to_string() },
			CertificateError::ChainValidationFailed { reason: "test".to_string() },
			CertificateError::UnsupportedVersion { version: 1 },
			CertificateError::CertificateSignatureVerificationFailed,
			CertificateError::CertificateDuplicateIncluded,
			CertificateError::CertificateOrphanFound,
			CertificateError::CertificateCycleFound,
		]
	}

	test_error_from_conversions! {
		test_error_conversions_with_real_errors, CertificateError, [
			crypto::operations::SignatureError::new(),
			crypto::error::CryptoError::InvalidKeyMaterial,
			crypto::error::CryptoError::SignatureError,
			asn1::error::Asn1Error::InvalidOid { reason: "test".to_string() },
			der::asn1::ObjectIdentifier::from_der(&[0xFF, 0xFF, 0xFF]).unwrap_err(),
			der::asn1::ObjectIdentifier::new("").unwrap_err(),
			base64::DecodeError::InvalidByte(0, b'!'),
		]
	}
}
