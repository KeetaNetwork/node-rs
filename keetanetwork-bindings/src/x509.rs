//! X.509 logic shared across binding boundaries: certificate-error reduction
//! and per-key-type dispatch for subject keys and signing.

use alloc::string::ToString;

use keetanetwork_account::GenericAccount;
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::certificates::Certificate;
use keetanetwork_x509::error::CertificateError;

use crate::error::CodedError;

/// Code for an account whose key type cannot sign or certify.
const UNSUPPORTED_KEY_TYPE: &str = "UNSUPPORTED_KEY_TYPE";

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

#[cfg(test)]
mod tests {
	use super::*;

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
}
