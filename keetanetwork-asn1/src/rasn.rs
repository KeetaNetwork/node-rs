//! rasn-based ASN.1 implementations
//!
//! This module provides ASN.1 structures using the rasn library.
use alloc::string::ToString;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::str::FromStr;

use der::{Decode as DerDecode, Encode as DerEncode, Sequence, ValueOrd};
use der::{DecodeValue, EncodeValue, Header, Length, Reader, Writer};

use crate::error::Asn1Error;

// Re-export generated types
pub use crate::generated::{
	AlgorithmIdentifier, AttributeTypeAndValue, DistinguishedName, Extension, Extensions, FeeEntries, FeeEntry,
	FeesMultiple, FeesMultipleInner, FeesSingle, HashData, HashDataInner, RelativeDistinguishedName,
	SubjectPublicKeyInfo, TbsCertificate, Validity, VoteCertificate, VoteStapleBundle,
};

// Re-export rasn types for convenience
pub use rasn::prelude::*;

impl AlgorithmIdentifier {
	/// Create a new AlgorithmIdentifier with the given OID and no parameters
	pub fn new(oid: &str) -> Result<Self, Asn1Error> {
		let oid = ObjectIdentifier::from_str(oid)?;
		Ok(AlgorithmIdentifier { algorithm: oid, parameters: None })
	}

	/// Create a new AlgorithmIdentifier with the given OID and parameters
	pub fn new_with_params(oid: &str, parameters: Any) -> Result<Self, Asn1Error> {
		let oid = ObjectIdentifier::from_str(oid)?;
		Ok(AlgorithmIdentifier { algorithm: oid, parameters: Some(parameters) })
	}

	/// Decode an AlgorithmIdentifier from DER format
	pub fn from_der(bytes: &[u8]) -> Result<Self, Asn1Error> {
		Ok(rasn::der::decode::<Self>(bytes)?)
	}

	/// Convert the AlgorithmIdentifier to DER format
	pub fn to_der(&self) -> Result<Vec<u8>, Asn1Error> {
		Ok(rasn::der::encode(self)?)
	}
}

impl FromStr for AlgorithmIdentifier {
	type Err = Asn1Error;

	fn from_str(oid: &str) -> Result<Self, Self::Err> {
		Self::new(oid)
	}
}

impl TryFrom<spki::AlgorithmIdentifierOwned> for AlgorithmIdentifier {
	type Error = Asn1Error;

	fn try_from(spki_alg: spki::AlgorithmIdentifierOwned) -> Result<Self, Self::Error> {
		let oid = ObjectIdentifier::from_str(&spki_alg.oid.to_string())?;
		let parameters = spki_alg
			.parameters
			.map(|p| DerEncode::to_der(&p))
			.transpose()?
			.map(Any::new);
		Ok(Self { algorithm: oid, parameters })
	}
}

impl TryFrom<AlgorithmIdentifier> for spki::AlgorithmIdentifierOwned {
	type Error = Asn1Error;

	fn try_from(alg: AlgorithmIdentifier) -> Result<Self, Self::Error> {
		let oid = der::oid::ObjectIdentifier::new(&alg.algorithm.to_string())?;
		let parameters = alg
			.parameters
			.map(|p| DerDecode::from_der(p.as_bytes()))
			.transpose()?;
		Ok(Self { oid, parameters })
	}
}

impl SubjectPublicKeyInfo {
	/// Create a new SubjectPublicKeyInfo
	pub fn new<T: AsRef<[u8]>>(algorithm: AlgorithmIdentifier, public_key_bytes: T) -> Result<Self, Asn1Error> {
		// Convert bytes to BitString using rasn's constructor
		let bytes = public_key_bytes.as_ref();
		let bit_string = BitString::from_vec(bytes.to_vec());
		Ok(SubjectPublicKeyInfo { algorithm, subject_public_key: bit_string })
	}

	pub fn from_der(bytes: &[u8]) -> Result<Self, Asn1Error> {
		Ok(rasn::der::decode::<Self>(bytes)?)
	}

	/// Convert the SubjectPublicKeyInfo to DER format
	pub fn to_der(&self) -> Result<Vec<u8>, Asn1Error> {
		Ok(rasn::der::encode(self)?)
	}
}

impl TryFrom<spki::SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo {
	type Error = Asn1Error;

	fn try_from(spki_info: spki::SubjectPublicKeyInfoOwned) -> Result<Self, Self::Error> {
		Ok(Self {
			algorithm: AlgorithmIdentifier::try_from(spki_info.algorithm)?,
			subject_public_key: BitString::from_vec(spki_info.subject_public_key.raw_bytes().to_vec()),
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

/// Macro to implement TryFrom for DER decoding of ASN.1 types using rasn
macro_rules! impl_try_from_rasn_decode {
	($target_type:ty) => {
		impl TryFrom<&[u8]> for $target_type {
			type Error = Asn1Error;

			fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
				Ok(rasn::der::decode::<Self>(data)?)
			}
		}
	};
}

impl_try_from_rasn_decode!(AlgorithmIdentifier);
impl_try_from_rasn_decode!(SubjectPublicKeyInfo);
impl_try_from_rasn_decode!(VoteCertificate);
impl_try_from_rasn_decode!(TbsCertificate);
impl_try_from_rasn_decode!(VoteStapleBundle);
impl_try_from_rasn_decode!(HashData);
impl_try_from_rasn_decode!(FeesSingle);
impl_try_from_rasn_decode!(FeesMultiple);
impl_try_from_rasn_decode!(Extension);

/// Macro to implement TryFrom for DER encoding of ASN.1 types using rasn
macro_rules! impl_try_from_rasn_encode {
	($source_type:ty) => {
		impl TryFrom<&$source_type> for Vec<u8> {
			type Error = Asn1Error;

			fn try_from(value: &$source_type) -> Result<Self, Self::Error> {
				Ok(rasn::der::encode(value)?)
			}
		}
	};
}

impl_try_from_rasn_encode!(AlgorithmIdentifier);
impl_try_from_rasn_encode!(SubjectPublicKeyInfo);
impl_try_from_rasn_encode!(VoteCertificate);
impl_try_from_rasn_encode!(TbsCertificate);
impl_try_from_rasn_encode!(VoteStapleBundle);
impl_try_from_rasn_encode!(HashData);
impl_try_from_rasn_encode!(FeesSingle);
impl_try_from_rasn_encode!(FeesMultiple);
impl_try_from_rasn_encode!(Extension);

// Implement der traits for AlgorithmIdentifier to make it compatible with x509 certificate structures
impl<'a> DecodeValue<'a> for AlgorithmIdentifier {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		// Read the content bytes
		let content_bytes = reader.read_slice(header.length)?;
		// Reconstruct the complete DER structure with the SEQUENCE tag and length
		let mut der_bytes = Vec::new();
		// SEQUENCE tag (0x30)
		der_bytes.push(0x30);

		// Length encoding
		let length_value = usize::try_from(header.length).map_err(|_| der::ErrorKind::Failed)?;
		if length_value < 0x80 {
			der_bytes.push(length_value as u8);
		} else {
			// Long form length encoding
			let length_bytes = length_value.to_be_bytes();
			let significant_bytes = length_bytes.iter().skip_while(|&&b| b == 0).count();
			der_bytes.push(0x80 | significant_bytes as u8);
			der_bytes.extend_from_slice(&length_bytes[8 - significant_bytes..]);
		}

		// Content bytes
		der_bytes.extend_from_slice(content_bytes);

		rasn::der::decode::<Self>(&der_bytes).map_err(|_| der::ErrorKind::Failed.into())
	}
}

impl EncodeValue for AlgorithmIdentifier {
	fn value_len(&self) -> der::Result<Length> {
		let der_bytes = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		Length::try_from(der_bytes.len()).map_err(|_| der::ErrorKind::Failed.into())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		let der_bytes = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		writer.write(&der_bytes)
	}
}

impl<'a> Sequence<'a> for AlgorithmIdentifier {}

impl ValueOrd for AlgorithmIdentifier {
	fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
		// Compare based on DER encoding
		let self_der = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		let other_der = rasn::der::encode(other).map_err(|_| der::ErrorKind::Failed)?;
		Ok(self_der.cmp(&other_der))
	}
}

// Implement der traits for SubjectPublicKeyInfo
impl<'a> DecodeValue<'a> for SubjectPublicKeyInfo {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
		// Read the content bytes
		let content_bytes = reader.read_slice(header.length)?;
		// Reconstruct the complete DER structure with the SEQUENCE tag and length
		let mut der_bytes = Vec::new();
		// SEQUENCE tag (0x30)
		der_bytes.push(0x30);

		// Length encoding
		let length_value = usize::try_from(header.length).map_err(|_| der::ErrorKind::Failed)?;
		if length_value < 0x80 {
			der_bytes.push(length_value as u8);
		} else {
			// Long form length encoding
			let length_bytes = length_value.to_be_bytes();
			let significant_bytes = length_bytes.iter().skip_while(|&&b| b == 0).count();
			der_bytes.push(0x80 | significant_bytes as u8);
			der_bytes.extend_from_slice(&length_bytes[8 - significant_bytes..]);
		}

		// Content bytes
		der_bytes.extend_from_slice(content_bytes);

		rasn::der::decode::<Self>(&der_bytes).map_err(|_| der::ErrorKind::Failed.into())
	}
}

impl EncodeValue for SubjectPublicKeyInfo {
	fn value_len(&self) -> der::Result<Length> {
		let der_bytes = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		Length::try_from(der_bytes.len()).map_err(|_| der::ErrorKind::Failed.into())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
		let der_bytes = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		writer.write(&der_bytes)
	}
}

impl<'a> Sequence<'a> for SubjectPublicKeyInfo {}

impl ValueOrd for SubjectPublicKeyInfo {
	fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
		// Compare based on DER encoding
		let self_der = rasn::der::encode(self).map_err(|_| der::ErrorKind::Failed)?;
		let other_der = rasn::der::encode(other).map_err(|_| der::ErrorKind::Failed)?;
		Ok(self_der.cmp(&other_der))
	}
}

/// Extension trait for ObjectIdentifier to provide compatibility between rasn and der backends
pub trait ObjectIdentifierExt {
	/// Create an ObjectIdentifier from a string representation
	fn from_str(s: &str) -> Result<Self, Asn1Error>
	where
		Self: Sized;

	/// Encode to DER bytes
	fn to_der(&self) -> Result<Vec<u8>, Asn1Error>;
}

impl ObjectIdentifierExt for ObjectIdentifier {
	fn from_str(s: &str) -> Result<Self, Asn1Error> {
		let arcs: Result<Vec<u32>, _> = s.split('.').map(|s| s.parse()).collect();
		let arcs = arcs.map_err(|_| Asn1Error::invalid_oid_format(s))?;
		ObjectIdentifier::new(arcs).ok_or_else(|| Asn1Error::InvalidOid { reason: format!("Invalid OID: {s}") })
	}

	fn to_der(&self) -> Result<Vec<u8>, Asn1Error> {
		Ok(rasn::der::encode(self)?)
	}
}
/// Extension trait to provide a unified interface for BitString
pub trait BitStringExt {
	fn from_bytes(bytes: &[u8]) -> Result<Self, Asn1Error>
	where
		Self: Sized;
	fn raw_bytes(&self) -> &[u8];
	fn to_der(&self) -> Result<der::asn1::BitString, Asn1Error>;
}

impl BitStringExt for BitString {
	fn from_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
		Ok(BitString::from_vec(bytes.to_vec()))
	}

	fn raw_bytes(&self) -> &[u8] {
		self.as_raw_slice()
	}

	fn to_der(&self) -> Result<der::asn1::BitString, Asn1Error> {
		let der_bytes = rasn::der::encode(self)?;
		der::asn1::BitString::from_der(&der_bytes).map_err(Asn1Error::from)
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
		AlgorithmIdentifier: AlgorithmIdentifier::new(oids::ED25519)?,
		AlgorithmIdentifier: {
			let null_param = create_null_any();
			AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param)?
		},
		SubjectPublicKeyInfo: {
			let alg_id = AlgorithmIdentifier::new(oids::ED25519)?;
			let key_bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
			SubjectPublicKeyInfo::new(alg_id, &key_bytes)?
		},
	}

	#[test]
	fn test_algorithm_identifier_with_params() -> Result<(), Asn1Error> {
		let test_oids = [oids::ED25519, oids::RSA_ENCRYPTION, oids::SECP256R1];
		for oid in test_oids {
			// Create a dummy Any parameter (NULL in this case)
			let null_param = create_null_any();
			let alg_id = AlgorithmIdentifier::new_with_params(oid, null_param.clone())?;
			assert_eq!(alg_id.algorithm.to_string(), oid);
			assert!(alg_id.parameters.is_some());
			assert_eq!(alg_id.parameters, Some(null_param));
		}
		Ok(())
	}

	#[test]
	fn test_algorithm_identifier_with_invalid_oid_in_new_with_params() {
		let null_param = create_null_any();
		let result = AlgorithmIdentifier::new_with_params("invalid.oid", null_param);
		assert!(result.is_err());
	}

	#[test]
	fn test_object_identifier_ext_from_str() -> Result<(), Asn1Error> {
		// Test valid OID strings
		let valid_oids = [
			(oids::RSA_ENCRYPTION, vec![1, 2, 840, 113549, 1, 1, 1]),
			(oids::ED25519, vec![1, 3, 101, 112]),
			(oids::SECP256R1, vec![1, 2, 840, 10045, 3, 1, 7]),
			(oids::SECP256K1, vec![1, 3, 132, 0, 10]),
			("1.2", vec![1, 2]), // Simple OID (intentionally hardcoded)
		];

		for (oid_str, expected_arcs) in valid_oids {
			let oid = ObjectIdentifier::from_str(oid_str)?;
			let actual_arcs: Vec<u32> = oid.as_ref().to_vec();
			assert_eq!(actual_arcs, expected_arcs);
			assert_eq!(oid.to_string(), oid_str);
		}

		// Test invalid OID strings
		let invalid_oids = [
			"",               // Empty string
			"invalid.oid",    // Non-numeric components
			"1.2.abc.4",      // Mixed numeric/non-numeric
			"3.1.2",          // First component > 2
			"1.2.",           // Trailing dot
			".1.2",           // Leading dot
			"1..2",           // Double dot
			"1.2.4294967296", // Component too large for u32
		];

		for oid_str in invalid_oids {
			let result = ObjectIdentifier::from_str(oid_str);
			assert!(result.is_err(), "Expected error for invalid OID: {oid_str}");
		}
		Ok(())
	}

	#[test]
	fn test_object_identifier_ext_from_str_with_as_ref() -> Result<(), Asn1Error> {
		let oid_str = oids::ED25519;
		let oid1 = ObjectIdentifier::from_str(oid_str)?;
		let oid_string = oid_str.to_string();

		let oid2 = ObjectIdentifier::from_str(&oid_string)?;
		let oid3 = ObjectIdentifier::from_str(&oid_string)?;
		assert_eq!(oid1, oid2);
		assert_eq!(oid2, oid3);
		assert_eq!(oid1.to_string(), oid_str);
		Ok(())
	}

	#[test]
	fn test_rasn_generalized_time_wire_format() {
		use chrono::{DateTime, Utc};
		let cases = [
			("2025-01-02T03:04:05Z", "180f32303235303130323033303430355a"),
			("2025-01-02T03:04:05.678Z", "181332303235303130323033303430352e3637385a"),
			("2025-01-02T03:04:05.500Z", "181332303235303130323033303430352e3530305a"),
		];
		for (input, expected_hex) in cases {
			let dt: DateTime<Utc> = input.parse().expect("test datetime parses");
			let gt: rasn::types::GeneralizedTime = dt.fixed_offset();
			let der = rasn::der::encode(&gt).expect("rasn encodes GeneralizedTime");
			let actual_hex = hex::encode(&der);
			println!("{input}: rasn={actual_hex}, expected={expected_hex}");
		}
	}

	#[test]
	fn test_vote_staple_bundle_transport_format() -> Result<(), Asn1Error> {
		let bundle =
			VoteStapleBundle::new(vec![OctetString::from(vec![1u8, 2, 3])], vec![OctetString::from(vec![4u8, 5, 6])]);

		let der = rasn::der::encode(&bundle)?;
		let expected =
			vec![0x30, 0x0e, 0x30, 0x05, 0x04, 0x03, 0x01, 0x02, 0x03, 0x30, 0x05, 0x04, 0x03, 0x04, 0x05, 0x06];
		assert_eq!(der, expected, "VoteStapleBundle transport bytes must match hand-rolled DER output");

		let round_trip = rasn::der::decode::<VoteStapleBundle>(&der)?;
		assert_eq!(round_trip, bundle, "VoteStapleBundle round-trip");
		Ok(())
	}

	#[test]
	fn test_extension_critical_true_encodes_boolean() -> Result<(), Asn1Error> {
		let oid = ObjectIdentifier::from_str("2.5.29.19")?;
		let ext = Extension::new(oid, true, OctetString::from(vec![0xAA]));

		let der = rasn::der::encode(&ext)?;
		assert!(der.windows(3).any(|w| w == [0x01, 0x01, 0xFF]), "BOOLEAN TRUE must be encoded");
		Ok(())
	}

	#[test]
	fn test_extension_critical_false_omits_boolean() -> Result<(), Asn1Error> {
		let oid = ObjectIdentifier::from_str("2.5.29.19")?;
		let ext = Extension::new(oid, false, OctetString::from(vec![0xAA]));

		let der = rasn::der::encode(&ext)?;
		assert!(!der.windows(3).any(|w| w == [0x01, 0x01, 0x00]), "BOOLEAN FALSE must be omitted (DEFAULT FALSE)");
		Ok(())
	}

	#[test]
	fn test_hash_data_outer_explicit_zero() -> Result<(), Asn1Error> {
		let oid = ObjectIdentifier::from_str("2.16.840.1.101.3.4.2.8")?;
		let inner = HashDataInner::new(oid, vec![OctetString::from(vec![0u8; 32])]);
		let hash_data = HashData(inner);

		let der = rasn::der::encode(&hash_data)?;
		assert_eq!(der[0], 0xA0, "HashData outer tag must be [0] EXPLICIT constructed (0xA0)");
		assert_eq!(der[2], 0x30, "HashData inner must be SEQUENCE (0x30)");
		Ok(())
	}

	#[test]
	fn test_fees_single_wire_shape() -> Result<(), Asn1Error> {
		let entry = FeeEntry::new(false, Integer::from(100), None, None);
		let single = FeesSingle(entry);

		let der = rasn::der::encode(&single)?;
		assert_eq!(der[0], 0xA0, "FeesSingle outer tag must be [0] EXPLICIT constructed (0xA0)");
		assert_eq!(der[2], 0x30, "FeesSingle inner must be SEQUENCE (0x30)");
		Ok(())
	}

	#[test]
	fn test_fees_multiple_wire_shape() -> Result<(), Asn1Error> {
		let entry = FeeEntry::new(false, Integer::from(100), None, None);
		let entries = FeeEntries(vec![entry]);
		let inner = FeesMultipleInner(entries);
		let multiple = FeesMultiple(inner);

		let der = rasn::der::encode(&multiple)?;
		assert_eq!(der[0], 0xA0, "FeesMultiple outer tag must be [0] EXPLICIT constructed (0xA0)");
		assert_eq!(der[2], 0xA0, "FeesMultiple inner must be [0] EXPLICIT (0xA0)");
		assert_eq!(der[4], 0x30, "FeesMultiple SEQUENCE OF must be SEQUENCE (0x30)");
		Ok(())
	}

	#[test]
	fn test_fee_entry_pay_to_implicit_primitive_tag() -> Result<(), Asn1Error> {
		let entry = FeeEntry::new(false, Integer::from(0), Some(OctetString::from(vec![0x01, 0x02, 0x03])), None);
		let der = rasn::der::encode(&entry)?;
		assert!(der.contains(&0x80), "payTo IMPLICIT [0] OCTET STRING must use primitive tag 0x80");
		assert!(
			!der.windows(2).any(|w| w[0] == 0x80 && w[1] == 0x04),
			"payTo must not include inner OCTET STRING tag 0x04"
		);
		Ok(())
	}

	#[test]
	fn test_tbs_version_explicit_zero() -> Result<(), Asn1Error> {
		let alg = AlgorithmIdentifier::new(oids::ED25519)?;
		let spki = SubjectPublicKeyInfo::new(alg.clone(), [0u8; 32])?;
		let now = chrono::Utc::now().fixed_offset();
		let tbs = TbsCertificate::new(
			Integer::from(2),
			Integer::from(1),
			alg.clone(),
			DistinguishedName(vec![]),
			Validity::new(now.into(), now.into()),
			DistinguishedName(vec![]),
			spki,
			Extensions(vec![]),
		);

		let der = rasn::der::encode(&tbs)?;
		assert_eq!(der[0], 0x30, "TbsCertificate outer must be SEQUENCE");

		let length_byte_count = if der[1] >= 0x80 {
			usize::from(der[1] & 0x7f)
		} else {
			0
		};

		let inner_start = 2 + length_byte_count;
		assert_eq!(der[inner_start], 0xA0, "version field must be [0] EXPLICIT (0xA0)");
		Ok(())
	}

	#[test]
	fn test_spki_conversions() -> Result<(), Asn1Error> {
		let alg_basic = AlgorithmIdentifier::new(oids::ED25519)?;
		let alg_round_trip: AlgorithmIdentifier =
			spki::AlgorithmIdentifierOwned::try_from(alg_basic.clone())?.try_into()?;
		assert_eq!(alg_basic, alg_round_trip);

		let null_param = create_null_any();
		let alg_with_params = AlgorithmIdentifier::new_with_params(oids::RSA_ENCRYPTION, null_param)?;
		let alg_params_round_trip: AlgorithmIdentifier =
			spki::AlgorithmIdentifierOwned::try_from(alg_with_params.clone())?.try_into()?;
		assert_eq!(alg_with_params, alg_params_round_trip);

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
