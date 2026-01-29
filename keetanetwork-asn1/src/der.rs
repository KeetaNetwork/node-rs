//! der-based ASN.1 implementations
//!
//! This module provides ASN.1 structures using the der library.

use core::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// Re-export commonly used types for convenience
pub use der::asn1::*;
pub use der::{Decode, Encode, Header, Reader, Sequence, SliceReader, Tag, TagNumber, Tagged, ValueOrd};

use crate::error::Asn1Error;

#[cfg(feature = "serde")]
pub use crate::utils::{
	deserialize_bit_string, deserialize_octet_string, deserialize_oid, serialize_bit_string, serialize_octet_string,
	serialize_oid,
};

/// Algorithm identifier structure according to RFC 5912 Section 5.
/// See: <https://datatracker.ietf.org/doc/html/rfc5912#section-5>
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm               OBJECT IDENTIFIER,
///     parameters              ANY DEFINED BY algorithm OPTIONAL
/// }
#[derive(Debug, Clone, PartialEq, Eq, Sequence, ValueOrd)]
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

impl TryFrom<spki::AlgorithmIdentifierOwned> for AlgorithmIdentifier {
	type Error = Asn1Error;

	fn try_from(spki_alg: spki::AlgorithmIdentifierOwned) -> Result<Self, Self::Error> {
		Ok(Self { algorithm: ObjectIdentifier::new(&spki_alg.oid.to_string())?, parameters: spki_alg.parameters })
	}
}

impl TryFrom<AlgorithmIdentifier> for spki::AlgorithmIdentifierOwned {
	type Error = Asn1Error;

	fn try_from(alg: AlgorithmIdentifier) -> Result<Self, Self::Error> {
		Ok(Self { oid: der::oid::ObjectIdentifier::new(&alg.algorithm.to_string())?, parameters: alg.parameters })
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
#[derive(Debug, Clone, PartialEq, Eq, Sequence, ValueOrd)]
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

impl TryFrom<spki::SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
	type Error = Asn1Error;

	fn try_from(spki_info: spki::SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
		Ok(Self {
			algorithm: AlgorithmIdentifier::try_from(spki_info.algorithm)?,
			subject_public_key: BitString::from_bytes(spki_info.subject_public_key.raw_bytes())?,
		})
	}
}

impl TryFrom<SubjectPublicKeyInfo> for spki::SubjectPublicKeyInfoOwned {
	type Error = Asn1Error;

	fn try_from(info: SubjectPublicKeyInfo) -> Result<Self, Self::Error> {
		Ok(Self {
			algorithm: spki::AlgorithmIdentifierOwned::try_from(info.algorithm)?,
			subject_public_key: der::asn1::BitString::from_bytes(info.subject_public_key.raw_bytes())?,
		})
	}
}

/// Macro to implement TryFrom for DER decoding of ASN.1 types
macro_rules! impl_try_from_der_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = Asn1Error;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				Ok(<Self as Decode>::from_der(data)?)
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
				Ok(<$source_type as Encode>::to_der(value)?)
			}
		}
	};
}

impl_try_from_der_encode_trait!(SubjectPublicKeyInfo);
impl_try_from_der_encode_trait!(AlgorithmIdentifier);

#[cfg(test)]
mod tests {
	use super::*;
	use crate::oids;

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

	crate::test_algorithm_identifier_with_params! {
		AlgorithmIdentifier,
		Any,
		test_oids: {
			oids::ED25519,
			oids::RSA_ENCRYPTION,
			oids::SECP256R1,
		}
	}

	crate::test_subject_public_key_info_key_sizes! {
		AlgorithmIdentifier,
		SubjectPublicKeyInfo,
		test_oid: oids::ED25519
	}

	crate::test_der_round_trip! {
		AlgorithmIdentifier: AlgorithmIdentifier::new(oids::ED25519)?,
		AlgorithmIdentifier: {
			let null_param = Any::from_der(&[0x05, 0x00])?;
			AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param)?
		},
		AlgorithmIdentifier: AlgorithmIdentifier::new(oids::SECP256R1)?,
		SubjectPublicKeyInfo: {
			let alg_id = AlgorithmIdentifier::new(oids::ED25519)?;
			let key_bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
			SubjectPublicKeyInfo::new(alg_id, &key_bytes)?
		},
	}

	#[test]
	fn test_spki_conversions() -> Result<(), Asn1Error> {
		// Test AlgorithmIdentifier round-trip
		let alg_basic = AlgorithmIdentifier::new(oids::ED25519)?;
		let alg_round_trip: AlgorithmIdentifier =
			spki::AlgorithmIdentifierOwned::try_from(alg_basic.clone())?.try_into()?;
		assert_eq!(alg_basic, alg_round_trip);

		let null_param = Any::from_der(&[0x05, 0x00])?;
		let alg_with_params = AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param)?;
		let alg_params_round_trip: AlgorithmIdentifier =
			spki::AlgorithmIdentifierOwned::try_from(alg_with_params.clone())?.try_into()?;
		assert_eq!(alg_with_params, alg_params_round_trip);

		// Test SubjectPublicKeyInfo round-trip
		let test_cases = [
			(oids::ED25519, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
			(oids::RSA_ENCRYPTION, vec![0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44]),
			(oids::SECP256R1, vec![0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
		];

		for (oid, key_bytes) in test_cases {
			let alg = AlgorithmIdentifier::new(oid)?;
			let info = SubjectPublicKeyInfo::new(alg, &key_bytes)?;
			let round_trip: SubjectPublicKeyInfo =
				spki::SubjectPublicKeyInfoOwned::try_from(info.clone())?.try_into()?;
			assert_eq!(info, round_trip);
		}
		Ok(())
	}
}
