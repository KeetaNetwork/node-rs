//! ASN.1 structures and utilities for cryptographic operations.
//!
//! This crate provides ASN.1 data structures commonly used in cryptographic
//! protocols, particularly X.509 certificates and related standards.

pub mod error;
pub mod oids;
pub mod utils;

use std::str::FromStr;

// Re-export commonly used types for convenience
pub use der::asn1::*;
pub use der::{Decode, Encode, Header, Reader, Sequence, SliceReader, Tag, TagNumber, Tagged, ValueOrd};
pub use error::Asn1Error;

#[cfg(feature = "serde")]
pub use utils::{
	deserialize_bit_string, deserialize_octet_string, deserialize_oid, serialize_bit_string, serialize_octet_string,
	serialize_oid,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Algorithm identifier structure according to RFC 5912 Section 5.
/// See: <https://datatracker.ietf.org/doc/html/rfc5912#section-5>
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AlgorithmIdentifier {
	/// Algorithm OID
	#[cfg_attr(feature = "serde", serde(serialize_with = "serialize_oid", deserialize_with = "deserialize_oid"))]
	pub algorithm: ObjectIdentifier,
	/// Raw ASN.1 parameters - can be NULL, absent, or any other type
	#[asn1(optional = "true")]
	#[cfg_attr(feature = "serde", serde(skip))]
	pub parameters: Option<Any>,
}

impl AlgorithmIdentifier {
	/// Create a new AlgorithmIdentifier with the given OID and no parameters
	pub fn new(oid: &str) -> Result<Self, Asn1Error> {
		Ok(Self { algorithm: ObjectIdentifier::new(oid)?, parameters: None })
	}

	/// Create a new AlgorithmIdentifier with the given OID and parameters
	pub fn new_with_params(oid: &str, parameters: Any) -> Result<Self, Asn1Error> {
		Ok(Self { algorithm: ObjectIdentifier::new(oid)?, parameters: Some(parameters) })
	}
}

impl FromStr for AlgorithmIdentifier {
	type Err = Asn1Error;

	fn from_str(oid: &str) -> Result<Self, Self::Err> {
		Self::new(oid)
	}
}

/// Public key information structure according to RFC 5912 Section 5.
/// See: <https://datatracker.ietf.org/doc/html/rfc5912#section-5>
///
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm              AlgorithmIdentifier,
///     subjectPublicKey       BIT STRING
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SubjectPublicKeyInfo {
	pub algorithm: AlgorithmIdentifier,
	#[cfg_attr(
		feature = "serde",
		serde(serialize_with = "serialize_bit_string", deserialize_with = "deserialize_bit_string")
	)]
	pub subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
	/// Create a new SubjectPublicKeyInfo
	pub fn new<T: AsRef<[u8]>>(algorithm: AlgorithmIdentifier, public_key_bytes: T) -> Result<Self, Asn1Error> {
		let public_key = BitString::from_bytes(public_key_bytes.as_ref())?;
		Ok(Self { algorithm, subject_public_key: public_key })
	}
}

/// Macro to implement TryFrom for DER decoding of ASN.1 types
macro_rules! impl_try_from_der_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = Asn1Error;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				<Self as Decode>::from_der(data).map_err(Asn1Error::from)
			}
		}
	};
}

impl_try_from_der_decode!(SubjectPublicKeyInfo);
impl_try_from_der_decode!(AlgorithmIdentifier);

/// Macro to implement TryFrom for DER encoding of ASN.1 types
macro_rules! impl_try_from_der_encode_trait {
	($source_type:ty) => {
		impl TryFrom<&$source_type> for Vec<u8> {
			type Error = Asn1Error;

			fn try_from(value: &$source_type) -> Result<Self, Self::Error> {
				<$source_type as Encode>::to_der(value).map_err(Asn1Error::from)
			}
		}
	};
}

impl_try_from_der_encode_trait!(SubjectPublicKeyInfo);
impl_try_from_der_encode_trait!(AlgorithmIdentifier);

#[cfg(test)]
mod tests {
	use super::*;

	/// Test cases for OIDs
	const TEST_OID_CASES: [&str; 3] = [oids::ED25519, oids::RSA_ENCRYPTION, oids::SECP256R1];

	macro_rules! test_algorithm_identifier {
		(
			valid: { $($valid_oid:expr),+ $(,)? }
			invalid: { $($invalid_oid:expr),+ $(,)? }
		) => {
			#[test]
			fn test_algorithm_identifier_valid_creation() {
				$(
					let alg_id = AlgorithmIdentifier::new($valid_oid).unwrap();
					assert_eq!(alg_id.algorithm.to_string(), $valid_oid);
					assert!(alg_id.parameters.is_none());
				)+
			}

			#[test]
			fn test_algorithm_identifier_invalid_creation() {
				$(
					let result = AlgorithmIdentifier::new($invalid_oid);
					assert!(result.is_err());
				)+
			}
		};
	}

	test_algorithm_identifier! {
		valid: {
			oids::ED25519,
			oids::RSA_ENCRYPTION,
			oids::SECP256R1,
		}
		invalid: {
			"invalid.oid",
			"",
			"not.a.valid.oid.format",
		}
	}

	#[test]
	fn test_subject_public_key_info_creation() {
		let test_cases = [
			(oids::ED25519, vec![0x01, 0x02, 0x03, 0x04]),
			(oids::RSA_ENCRYPTION, vec![0xAB, 0xCD, 0xEF]),
			(oids::SECP256R1, vec![0xFF, 0x00, 0x11, 0x22]),
		];

		for (oid, public_key_bytes) in test_cases {
			let alg_id = AlgorithmIdentifier::new(oid).unwrap();
			let spki = SubjectPublicKeyInfo::new(alg_id, &public_key_bytes).unwrap();
			assert_eq!(spki.subject_public_key.raw_bytes(), &public_key_bytes);
		}
	}

	macro_rules! test_try_from_conversions {
		(
			valid: { $($valid_input:expr => $valid_expected:expr),+ $(,)? }
			invalid: { $($invalid_input:expr),+ $(,)? }
		) => {
			#[test]
			fn test_try_from_valid_oids() {
				$(
					// Test &str conversion
					let alg_id: AlgorithmIdentifier = $valid_input.parse().unwrap();
					assert_eq!(alg_id.algorithm.to_string(), $valid_expected);
					assert!(alg_id.parameters.is_none());

					// Test String conversion
					let oid_string = $valid_input.to_string();
					let alg_id: AlgorithmIdentifier = oid_string.parse().unwrap();
					assert_eq!(alg_id.algorithm.to_string(), $valid_expected);
					assert!(alg_id.parameters.is_none());
				)+
			}

			#[test]
			fn test_try_from_invalid_oids() {
				$(
					// Test &str conversion fails
					let result: Result<AlgorithmIdentifier, _> = $invalid_input.parse();
					assert!(result.is_err());

					// Test String conversion fails
					let oid_string = $invalid_input.to_string();
					let result: Result<AlgorithmIdentifier, _> = oid_string.parse();
					assert!(result.is_err());
				)+
			}
		};
	}

	test_try_from_conversions! {
		valid: {
			oids::ED25519 => oids::ED25519,
			oids::SECP256R1 => oids::SECP256R1,
			oids::SECP256K1 => oids::SECP256K1,
			oids::RSA_ENCRYPTION => oids::RSA_ENCRYPTION,
		}
		invalid: {
			"invalid.oid",
			"",
		}
	}

	#[test]
	fn test_algorithm_identifier_with_params() {
		for oid in TEST_OID_CASES {
			// Create a dummy Any parameter (NULL in this case)
			let null_param = Any::from_der(&[0x05, 0x00]).unwrap(); // ASN.1 NULL
			let alg_id = AlgorithmIdentifier::new_with_params(oid, null_param.clone()).unwrap();

			assert_eq!(alg_id.algorithm.to_string(), oid);
			assert!(alg_id.parameters.is_some());
			assert_eq!(alg_id.parameters.unwrap(), null_param);
		}
	}

	#[test]
	fn test_algorithm_identifier_with_invalid_oid_in_new_with_params() {
		let null_param = Any::from_der(&[0x05, 0x00]).unwrap();
		let result = AlgorithmIdentifier::new_with_params("invalid.oid", null_param);
		assert!(result.is_err());
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_subject_public_key_info_with_invalid_bit_string() {
		// Test with empty key bytes
		let alg_id = AlgorithmIdentifier::new(oids::ED25519).unwrap();
		let empty_key_result = SubjectPublicKeyInfo::new(alg_id.clone(), []);
		assert!(empty_key_result.is_ok()); // Empty bytes should be valid for BitString

		// Test with various key sizes
		let test_sizes = [1, 32, 64, 65, 256];
		for size in test_sizes {
			let key_bytes = vec![0x42; size];

			// Test with valid key bytes
			let spki_result = SubjectPublicKeyInfo::new(alg_id.clone(), &key_bytes);
			assert!(spki_result.is_ok());

			// Verify the created SubjectPublicKeyInfo
			let spki = spki_result.unwrap();
			assert_eq!(spki.subject_public_key.raw_bytes(), &key_bytes);
		}
	}

	macro_rules! test_der_encoding_decoding {
		($($struct_type:ty: $create_fn:expr),+ $(,)?) => {
			#[test]
			fn test_der_round_trip() {
				$(
					let original: $struct_type = $create_fn;

					// Test encoding to DER bytes
					let der_bytes: Vec<u8> = (&original).try_into().unwrap();
					assert!(!der_bytes.is_empty());

					// Test decoding from DER bytes
					let decoded: $struct_type = der_bytes.as_slice().try_into().unwrap();
					// Verify round-trip equality
					assert_eq!(original, decoded);
				)+
			}
		};
	}

	test_der_encoding_decoding! {
		AlgorithmIdentifier: AlgorithmIdentifier::new(oids::ED25519).unwrap(),
		AlgorithmIdentifier: {
			let null_param = Any::from_der(&[0x05, 0x00]).unwrap();
			AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param).unwrap()
		},
		SubjectPublicKeyInfo: {
			let alg_id = AlgorithmIdentifier::new(oids::ED25519).unwrap();
			let key_bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
			SubjectPublicKeyInfo::new(alg_id, &key_bytes).unwrap()
		},
	}
}
