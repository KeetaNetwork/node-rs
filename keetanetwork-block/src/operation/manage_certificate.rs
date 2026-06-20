//! MANAGE_CERTIFICATE operation: add or remove an X.509 certificate.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use keetanetwork_crypto::hash::hash_default;

use crate::error::BlockError;

use super::{AdjustMethod, BlockOperation, OperationContext, OperationType};

/// DER bytes of an X.509 certificate.
///
/// Stored as raw bytes for transport fidelity; with the `x509` feature the
/// certificate can be parsed into a typed [`keetanetwork_x509`] certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl CertificateDer {
	/// The raw DER bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// The certificate hash (SHA3-256 of the DER bytes), as used for
	/// duplicate detection and `MANAGE_CERTIFICATE` removals.
	pub fn hash(&self) -> [u8; 32] {
		hash_default(&self.0)
	}

	/// Parse into a typed certificate.
	pub fn to_certificate(&self) -> Result<keetanetwork_x509::certificates::Certificate, BlockError> {
		Ok(keetanetwork_x509::certificates::Certificate::try_from(self.0.as_slice())?)
	}
}

impl From<Vec<u8>> for CertificateDer {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes)
	}
}

impl TryFrom<&keetanetwork_x509::certificates::Certificate> for CertificateDer {
	type Error = BlockError;

	fn try_from(certificate: &keetanetwork_x509::certificates::Certificate) -> Result<Self, Self::Error> {
		Ok(Self(certificate.to_der()?))
	}
}

/// A certificate referenced either by value or by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateOrHash {
	/// The full certificate (used when adding)
	Certificate(CertificateDer),
	/// The certificate hash (used when removing)
	Hash([u8; 32]),
}

impl CertificateOrHash {
	/// The certificate hash for duplicate detection.
	pub fn hash(&self) -> [u8; 32] {
		match self {
			CertificateOrHash::Certificate(certificate) => certificate.hash(),
			CertificateOrHash::Hash(hash) => *hash,
		}
	}
}

impl From<CertificateDer> for CertificateOrHash {
	fn from(certificate: CertificateDer) -> Self {
		CertificateOrHash::Certificate(certificate)
	}
}

impl From<[u8; 32]> for CertificateOrHash {
	fn from(hash: [u8; 32]) -> Self {
		CertificateOrHash::Hash(hash)
	}
}

/// Intermediate certificates accompanying a MANAGE_CERTIFICATE add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntermediateCertificates {
	/// No intermediates (encoded as NULL)
	None,
	/// A possibly empty certificate bundle (encoded as a SEQUENCE)
	Bundle(Vec<CertificateDer>),
}

/// MANAGE_CERTIFICATE: add or remove an X.509 certificate.
#[derive(Debug, Clone)]
pub struct ManageCertificate {
	/// Add or Subtract (SET is forbidden)
	pub method: AdjustMethod,
	/// The certificate (add) or its hash (remove)
	pub certificate_or_hash: CertificateOrHash,
	/// Intermediate certificates; present exactly when adding
	pub intermediate_certificates: Option<IntermediateCertificates>,
}

impl BlockOperation for ManageCertificate {
	const TYPE: OperationType = OperationType::ManageCertificate;

	fn validate(&self, ctx: &OperationContext<'_>) -> Result<(), BlockError> {
		if self.method == AdjustMethod::Set {
			return Err(BlockError::AdjustMethodSetForbidden);
		}

		if self.intermediate_certificates.is_none() == (self.method == AdjustMethod::Add) {
			return Err(BlockError::IntermediateCertificatesOnlyAdd);
		}

		if self.method == AdjustMethod::Add {
			let CertificateOrHash::Certificate(certificate) = &self.certificate_or_hash else {
				return Err(BlockError::InvalidCertificateValue);
			};

			let parsed = certificate.to_certificate()?;
			let subject_key = &parsed
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key;

			let account_bytes = ctx.account.to_public_key_with_type();
			if subject_key.raw_bytes() != &account_bytes[1..] {
				return Err(BlockError::CertificateSubjectMismatch);
			}
		}

		let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
		for other in ctx.iter_type::<ManageCertificate>() {
			if !seen.insert(other.certificate_or_hash.hash()) {
				return Err(BlockError::DuplicateCertificateOperation);
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use super::*;
	use crate::operation::harness::{assert_validation, manage_certificate_subtract, Harness};
	use crate::operation::Operation;
	use crate::testing::generate_ed25519_ref;

	#[test]
	fn test_certificate_or_hash_from() {
		let certificate = CertificateDer::from(Vec::from([1u8, 2, 3]));
		assert!(matches!(CertificateOrHash::from(certificate), CertificateOrHash::Certificate(_)));
		assert!(matches!(CertificateOrHash::from([7u8; 32]), CertificateOrHash::Hash(_)));
	}

	#[test]
	fn test_manage_certificate_validation() {
		assert_validation! {
			"rejects_set_method": {
				let mut operation = manage_certificate_subtract(7);
				operation.method = AdjustMethod::Set;
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::AdjustMethodSetForbidden),
			"rejects_intermediates_on_subtract": {
				let mut operation = manage_certificate_subtract(7);
				operation.intermediate_certificates = Some(IntermediateCertificates::None);
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::IntermediateCertificatesOnlyAdd),
			"rejects_hash_on_add": {
				let mut operation = manage_certificate_subtract(7);
				operation.method = AdjustMethod::Add;
				operation.intermediate_certificates = Some(IntermediateCertificates::None);
				(Harness::new(generate_ed25519_ref(1)), operation.into())
			} => Err(BlockError::InvalidCertificateValue),
			"rejects_duplicate_certificate": {
				let mut harness = Harness::new(generate_ed25519_ref(1));
				let operation: Operation = manage_certificate_subtract(7).into();
				harness.operations = vec![operation.clone(), operation.clone()];
				(harness, operation)
			} => Err(BlockError::DuplicateCertificateOperation),
		}
	}
}
