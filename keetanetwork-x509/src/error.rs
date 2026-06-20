use alloc::format;
use alloc::string::String;

use keetanetwork_utils::{impl_error_from_with_fields, impl_variant_error_from};
use snafu::Snafu;

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
	/// Too many certificates in the graph
	#[snafu(display("Certificate graph exceeds the maximum of {max} certificates"))]
	CertificateInvalidGraphCount { max: usize },
}

/// Maps any backend error to [`CertificateError::InvalidCertificate`],
/// collapsing the repeated discard closure at call sites.
pub(crate) trait OrInvalidCertificate<T> {
	fn or_invalid_certificate(self) -> Result<T, CertificateError>;
}

impl<T, E> OrInvalidCertificate<T> for Result<T, E> {
	fn or_invalid_certificate(self) -> Result<T, CertificateError> {
		self.map_err(|_| CertificateError::InvalidCertificate)
	}
}

// Use macros for simple variant mappings
impl_variant_error_from!(CertificateError, {
	der::oid::Error => InvalidCertificate,
	base64::DecodeError => InvalidCertificate,
	keetanetwork_crypto::operations::SignatureError => CertificateSignatureVerificationFailed,
});

// Use macros for field transformations
impl_error_from_with_fields!(CertificateError, {
	der::Error => Asn1ParseError { message: |error: der::Error| format!("DER error: {error}") },
	keetanetwork_crypto::error::CryptoError => Asn1ParseError { message: |error: keetanetwork_crypto::error::CryptoError| format!("Crypto error: {error}") },
	keetanetwork_asn1::error::Asn1Error => Asn1ParseError { message: |error: keetanetwork_asn1::error::Asn1Error| format!("ASN.1 error: {error}") },
});

#[cfg(test)]
mod tests {
	use der::Decode;

	use super::*;
	use keetanetwork_utils::{test_error_from_conversions, test_error_variants};

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
			CertificateError::CertificateInvalidGraphCount { max: 10 },
		]
	}

	test_error_from_conversions! {
		test_error_conversions_with_real_errors, CertificateError, [
			keetanetwork_crypto::operations::SignatureError::new(),
			keetanetwork_crypto::error::CryptoError::InvalidKeyMaterial,
			keetanetwork_crypto::error::CryptoError::SignatureError,
			keetanetwork_asn1::error::Asn1Error::InvalidOid { reason: "test".to_string() },
			der::asn1::ObjectIdentifier::from_der(&[0xFF, 0xFF, 0xFF]).unwrap_err(),
			der::asn1::ObjectIdentifier::new("").unwrap_err(),
			base64::DecodeError::InvalidByte(0, b'!'),
		]
	}
}
