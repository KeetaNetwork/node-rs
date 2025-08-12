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
}

impl From<der::Error> for CertificateError {
	fn from(error: der::Error) -> Self {
		CertificateError::Asn1ParseError { message: format!("DER error: {error}") }
	}
}

impl From<der::oid::Error> for CertificateError {
	fn from(_error: der::oid::Error) -> Self {
		CertificateError::InvalidCertificate
	}
}

impl From<base64::DecodeError> for CertificateError {
	fn from(_error: base64::DecodeError) -> Self {
		CertificateError::InvalidCertificate
	}
}

impl From<crypto::error::CryptoError> for CertificateError {
	fn from(error: crypto::error::CryptoError) -> Self {
		CertificateError::Asn1ParseError { message: format!("Crypto error: {error}") }
	}
}

impl From<crypto::operations::SignatureError> for CertificateError {
	fn from(_error: crypto::operations::SignatureError) -> Self {
		CertificateError::CertificateSignatureVerificationFailed
	}
}

impl From<asn1::error::Asn1Error> for CertificateError {
	fn from(error: asn1::error::Asn1Error) -> Self {
		CertificateError::Asn1ParseError { message: format!("ASN.1 error: {error}") }
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use der::asn1::ObjectIdentifier;
	use der::Decode;

	#[test]
	fn test_certificate_error_clone_and_partial_eq() {
		let error1 = CertificateError::InvalidCertificate;
		let error2 = error1.clone();
		assert_eq!(error1, error2);

		let error3 = CertificateError::Expired;
		assert_ne!(error1, error3);

		// Test with data-carrying variants
		let error4 = CertificateError::ValidationFailed { reason: "test".to_string() };
		let error5 = error4.clone();
		assert_eq!(error4, error5);

		let error6 = CertificateError::ValidationFailed { reason: "different".to_string() };
		assert_ne!(error4, error6);
	}

	#[test]
	fn test_certificate_error_debug() {
		let error = CertificateError::InvalidCertificate;
		let debug_str = format!("{error:?}");
		assert!(debug_str.contains("InvalidCertificate"));

		let error = CertificateError::MissingField { field: "test".to_string() };
		let debug_str = format!("{error:?}");
		assert!(debug_str.contains("MissingField"));
		assert!(debug_str.contains("test"));
	}

	#[test]
	fn test_der_error_conversion() {
		// Create a DER error by trying to decode and invalid ObjectIdentifier
		let invalid_der = &[0xFF, 0xFF, 0xFF];
		let der_error = ObjectIdentifier::from_der(invalid_der).unwrap_err();
		let cert_error: CertificateError = der_error.into();
		assert!(matches!(cert_error, CertificateError::Asn1ParseError { .. }));
	}

	#[test]
	fn test_oid_error_conversion() {
		// Create an OID error by trying to create an invalid ObjectIdentifier
		let oid_error = ObjectIdentifier::new("").unwrap_err();
		let cert_error: CertificateError = oid_error.into();
		assert_eq!(cert_error, CertificateError::InvalidCertificate);
	}

	#[test]
	fn test_base64_error_conversion() {
		let base64_error = base64::DecodeError::InvalidByte(0, b'!');
		let cert_error: CertificateError = base64_error.into();
		assert_eq!(cert_error, CertificateError::InvalidCertificate);
	}

	#[test]
	fn test_crypto_error_conversion() {
		let crypto_error = crypto::error::CryptoError::InvalidPrivateKey;
		let cert_error: CertificateError = crypto_error.into();
		assert!(matches!(cert_error, CertificateError::Asn1ParseError { .. }));
	}

	#[test]
	fn test_signature_error_conversion() {
		let signature_error = crypto::operations::SignatureError::new();
		let cert_error: CertificateError = signature_error.into();
		assert_eq!(cert_error, CertificateError::CertificateSignatureVerificationFailed);
	}

	#[test]
	fn test_asn1_error_conversion() {
		let asn1_error = asn1::error::Asn1Error::InvalidOid { reason: "test".to_string() };
		let cert_error: CertificateError = asn1_error.into();
		assert!(matches!(cert_error, CertificateError::Asn1ParseError { .. }));
	}
}
