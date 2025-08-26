//! rasn-based ASN.1 implementations
//!
//! This module provides ASN.1 structures using the rasn library.

// Re-export generated types
pub use crate::generated::{AlgorithmIdentifier, SubjectPublicKeyInfo};

// Re-export rasn types for convenience
pub use rasn::prelude::*;

impl AlgorithmIdentifier {
	/// Create a new AlgorithmIdentifier with the given OID and no parameters
	pub fn new(oid: &str) -> Result<Self, crate::error::Asn1Error> {
		// Parse OID string manually into numeric components
		let arcs: Result<Vec<u32>, _> = oid.split('.').map(|s| s.parse::<u32>()).collect();
		let arcs =
			arcs.map_err(|_| crate::error::Asn1Error::InvalidOid { reason: format!("Invalid OID format: {}", oid) })?;

		let oid = ObjectIdentifier::new(arcs)
			.ok_or_else(|| crate::error::Asn1Error::InvalidOid { reason: format!("Invalid OID: {}", oid) })?;

		// Use the generated type's constructor with the native OID type
		Ok(AlgorithmIdentifier { algorithm: oid, parameters: None })
	}

	/// Create a new AlgorithmIdentifier with the given OID and parameters
	pub fn new_with_params(oid: &str, parameters: Any) -> Result<Self, crate::error::Asn1Error> {
		// Parse OID string manually into numeric components
		let arcs: Result<Vec<u32>, _> = oid.split('.').map(|s| s.parse::<u32>()).collect();
		let arcs =
			arcs.map_err(|_| crate::error::Asn1Error::InvalidOid { reason: format!("Invalid OID format: {}", oid) })?;

		let oid = ObjectIdentifier::new(arcs)
			.ok_or_else(|| crate::error::Asn1Error::InvalidOid { reason: format!("Invalid OID: {}", oid) })?;

		// Use the generated type's constructor with the native OID type
		Ok(AlgorithmIdentifier { algorithm: oid, parameters: Some(parameters) })
	}
}

impl std::str::FromStr for AlgorithmIdentifier {
	type Err = crate::error::Asn1Error;

	fn from_str(oid: &str) -> Result<Self, Self::Err> {
		Self::new(oid)
	}
}

impl SubjectPublicKeyInfo {
	/// Create a new SubjectPublicKeyInfo
	pub fn new<T: AsRef<[u8]>>(
		algorithm: AlgorithmIdentifier,
		public_key_bytes: T,
	) -> Result<Self, crate::error::Asn1Error> {
		// Convert bytes to BitString using rasn's constructor
		let bytes = public_key_bytes.as_ref();
		let bit_string = BitString::from_vec(bytes.to_vec());
		Ok(SubjectPublicKeyInfo { algorithm, subject_public_key: bit_string })
	}
}

/// Macro to implement TryFrom for DER decoding of ASN.1 types using rasn
macro_rules! impl_try_from_rasn_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = crate::error::Asn1Error;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				Ok(rasn::der::decode::<Self>(data)?)
			}
		}
	};
}

impl_try_from_rasn_decode!(AlgorithmIdentifier);
impl_try_from_rasn_decode!(SubjectPublicKeyInfo);

/// Macro to implement TryFrom for DER encoding of ASN.1 types using rasn
macro_rules! impl_try_from_rasn_encode {
	($source_type:ty) => {
		impl TryFrom<&$source_type> for Vec<u8> {
			type Error = crate::error::Asn1Error;

			fn try_from(value: &$source_type) -> Result<Self, Self::Error> {
				Ok(rasn::der::encode(value)?)
			}
		}
	};
}

impl_try_from_rasn_encode!(AlgorithmIdentifier);
impl_try_from_rasn_encode!(SubjectPublicKeyInfo);

/// Extension trait to provide a unified interface for BitString
pub trait BitStringExt {
	fn raw_bytes(&self) -> &[u8];
}

impl BitStringExt for BitString {
	fn raw_bytes(&self) -> &[u8] {
		self.as_raw_slice()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::oids;

	// Helper function to create Any for rasn backend
	fn create_null_any() -> Any {
		Any::new(vec![0x05, 0x00]) // ASN.1 NULL
	}

	crate::test_algorithm_identifier! {
		AlgorithmIdentifier,
		valid: {
			oids::ED25519,
			oids::RSA_ENCRYPTION,
			oids::SECP256R1,
		},
		invalid: {
			"invalid.oid",
			"",
			"not.a.valid.oid.format",
		}
	}

	crate::test_subject_public_key_info! {
		AlgorithmIdentifier,
		SubjectPublicKeyInfo,
		test_cases: {
			oids::ED25519, vec![0x01, 0x02, 0x03, 0x04],
			oids::RSA_ENCRYPTION, vec![0xAB, 0xCD, 0xEF],
			oids::SECP256R1, vec![0xFF, 0x00, 0x11, 0x22],
		}
	}

	crate::test_algorithm_identifier_try_from! {
		AlgorithmIdentifier,
		valid: {
			oids::ED25519 => oids::ED25519,
			oids::SECP256R1 => oids::SECP256R1,
			oids::SECP256K1 => oids::SECP256K1,
			oids::RSA_ENCRYPTION => oids::RSA_ENCRYPTION,
		},
		invalid: {
			"invalid.oid",
			"",
		}
	}

	crate::test_subject_public_key_info_key_sizes! {
		AlgorithmIdentifier,
		SubjectPublicKeyInfo,
		test_oid: oids::ED25519
	}

	crate::test_der_round_trip! {
		AlgorithmIdentifier: AlgorithmIdentifier::new(oids::ED25519).unwrap(),
		AlgorithmIdentifier: {
			let null_param = create_null_any();
			AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param).unwrap()
		},
		SubjectPublicKeyInfo: {
			let alg_id = AlgorithmIdentifier::new(oids::ED25519).unwrap();
			let key_bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
			SubjectPublicKeyInfo::new(alg_id, &key_bytes).unwrap()
		},
	}

	#[test]
	fn test_algorithm_identifier_with_params() {
		let test_oids = [oids::ED25519, oids::RSA_ENCRYPTION, oids::SECP256R1];
		for oid in test_oids {
			// Create a dummy Any parameter (NULL in this case)
			let null_param = create_null_any();
			let alg_id = AlgorithmIdentifier::new_with_params(oid, null_param.clone()).unwrap();

			assert_eq!(alg_id.algorithm.to_string(), oid);
			assert!(alg_id.parameters.is_some());
			assert_eq!(alg_id.parameters.unwrap(), null_param);
		}
	}

	#[test]
	fn test_algorithm_identifier_with_invalid_oid_in_new_with_params() {
		let null_param = create_null_any();
		let result = AlgorithmIdentifier::new_with_params("invalid.oid", null_param);
		assert!(result.is_err());
	}
}
