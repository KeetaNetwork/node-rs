//! Utilities for working with ASN.1 types

use std::collections::HashMap;

use crate::error::Asn1Error;

// Import ObjectIdentifier (always needed for utils functions)
#[cfg(feature = "der")]
use crate::der::ObjectIdentifier;

#[cfg(all(feature = "rasn", not(feature = "der")))]
use crate::rasn::ObjectIdentifier;

// Import additional types for serde functionality only when serde is enabled
#[cfg(all(feature = "der", feature = "serde"))]
use crate::der::{BitString, OctetString};

#[cfg(all(feature = "rasn", not(feature = "der"), feature = "serde"))]
use crate::{BitString, BitStringExt, OctetString};

#[cfg(feature = "serde")]
use serde::Deserialize;

/// Serialize an ObjectIdentifier
#[cfg(feature = "serde")]
pub fn serialize_oid<S>(oid: &ObjectIdentifier, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&oid.to_string())
}

/// Deserialize an ObjectIdentifier
#[cfg(feature = "serde")]
pub fn deserialize_oid<'de, D>(deserializer: D) -> Result<ObjectIdentifier, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;

	#[cfg(feature = "der")]
	{
		ObjectIdentifier::new(&s).map_err(serde::de::Error::custom)
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		// Parse OID string manually into numeric components for rasn
		let arcs: Result<Vec<u32>, _> = s.split('.').map(|s| s.parse::<u32>()).collect();
		let arcs = arcs.map_err(serde::de::Error::custom)?;
		ObjectIdentifier::new(arcs).ok_or_else(|| serde::de::Error::custom("Invalid OID"))
	}
}

/// Serialize an OctetString
#[cfg(feature = "serde")]
pub fn serialize_octet_string<S>(octet_string: &OctetString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	#[cfg(feature = "der")]
	{
		serializer.serialize_str(&hex::encode(octet_string.as_bytes()))
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		serializer.serialize_str(&hex::encode(octet_string))
	}
}

/// Deserialize an OctetString
#[cfg(feature = "serde")]
pub fn deserialize_octet_string<'de, D>(deserializer: D) -> Result<OctetString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

	#[cfg(feature = "der")]
	{
		OctetString::new(&*bytes).map_err(serde::de::Error::custom)
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		Ok(OctetString::from_slice(&bytes))
	}
}

/// Serialize a BitString
#[cfg(feature = "serde")]
pub fn serialize_bit_string<S>(bit_string: &BitString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	#[cfg(feature = "der")]
	{
		serializer.serialize_str(&hex::encode(bit_string.raw_bytes()))
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		serializer.serialize_str(&hex::encode(bit_string.raw_bytes()))
	}
}

/// Deserialize a BitString
#[cfg(feature = "serde")]
pub fn deserialize_bit_string<'de, D>(deserializer: D) -> Result<BitString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

	#[cfg(feature = "der")]
	{
		BitString::from_bytes(&bytes).map_err(serde::de::Error::custom)
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		Ok(BitString::from_vec(bytes))
	}
}

/// Get an OID string by algorithm name from an OID database
pub fn get_oid(name: &str, oid_db: &HashMap<&str, &str>) -> Result<ObjectIdentifier, Asn1Error> {
	let oid_str = oid_db
		.get(name)
		.ok_or_else(|| Asn1Error::InvalidOid { reason: format!("Unknown algorithm: {name}") })?;

	#[cfg(feature = "der")]
	{
		ObjectIdentifier::new(oid_str).map_err(|_| Asn1Error::InvalidOid {
			reason: format!("Invalid OID format for algorithm {name}: {oid_str}"),
		})
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		// Parse OID string manually into numeric components for rasn
		let arcs: Result<Vec<u32>, _> = oid_str.split('.').map(|s| s.parse::<u32>()).collect();
		let arcs = arcs.map_err(|_| Asn1Error::InvalidOid {
			reason: format!("Invalid OID format for algorithm {name}: {oid_str}"),
		})?;

		ObjectIdentifier::new(arcs).ok_or_else(|| Asn1Error::InvalidOid {
			reason: format!("Invalid OID format for algorithm {name}: {oid_str}"),
		})
	}
}

/// Look up an algorithm name by OID from an OID database.
pub fn lookup_by_oid<'a>(oid: &str, oid_db: &'a HashMap<&'a str, &'a str>) -> Result<&'a str, Asn1Error> {
	oid_db
		.iter()
		.find(|(_, &o)| o == oid)
		.map(|(&name, _)| name)
		.ok_or_else(|| Asn1Error::InvalidOid { reason: format!("Unknown OID: {oid}") })
}

/// Look up an algorithm name by ObjectIdentifier from an OID database.
pub fn lookup_by_object_identifier<'a>(
	oid: &ObjectIdentifier,
	oid_db: &'a HashMap<&'a str, &'a str>,
) -> Result<&'a str, Asn1Error> {
	let oid_str = oid.to_string();
	lookup_by_oid(&oid_str, oid_db)
}

/// Parse an OID string into an ObjectIdentifier.
pub fn parse_oid_string(oid_str: &str) -> Result<ObjectIdentifier, Asn1Error> {
	#[cfg(feature = "der")]
	{
		ObjectIdentifier::new(oid_str)
			.map_err(|_| Asn1Error::InvalidOid { reason: format!("Invalid OID format: {oid_str}") })
	}

	#[cfg(all(feature = "rasn", not(feature = "der")))]
	{
		// Parse OID string manually into numeric components for rasn
		let arcs: Result<Vec<u32>, _> = oid_str.split('.').map(|s| s.parse::<u32>()).collect();
		let arcs = arcs.map_err(|_| Asn1Error::InvalidOid { reason: format!("Invalid OID format: {oid_str}") })?;

		ObjectIdentifier::new(arcs)
			.ok_or_else(|| Asn1Error::InvalidOid { reason: format!("Invalid OID format: {oid_str}") })
	}
}

/// Validate that an OID string contains only valid components.
pub fn validate_oid_format(oid_str: &str) -> Result<Vec<u32>, Asn1Error> {
	if oid_str.is_empty() {
		return Err(Asn1Error::InvalidOid { reason: "OID string cannot be empty".to_string() });
	}

	oid_str
		.split('.')
		.map(|s| {
			s.parse::<u32>()
				.map_err(|e| Asn1Error::InvalidOid { reason: format!("Invalid OID component '{s}': {e}") })
		})
		.collect()
}

/// Macro to test AlgorithmIdentifier creation with valid and invalid OIDs
#[macro_export]
macro_rules! test_algorithm_identifier {
	(
		$algorithm_identifier_type:ty,
		valid: { $($valid_oid:expr),+ $(,)? },
		invalid: { $($invalid_oid:expr),+ $(,)? }
	) => {
		#[test]
		fn test_algorithm_identifier_valid_creation() {
			$(
				let alg_id = <$algorithm_identifier_type>::new($valid_oid).unwrap();
				assert_eq!(alg_id.algorithm.to_string(), $valid_oid);
				assert!(alg_id.parameters.is_none());
			)+
		}

		#[test]
		fn test_algorithm_identifier_invalid_creation() {
			$(
				let result = <$algorithm_identifier_type>::new($invalid_oid);
				assert!(result.is_err());
			)+
		}
	};
}

/// Macro to test SubjectPublicKeyInfo creation
#[macro_export]
macro_rules! test_subject_public_key_info {
	(
		$algorithm_identifier_type:ty,
		$subject_public_key_info_type:ty,
		test_cases: { $($oid:expr, $key_bytes:expr),+ $(,)? }
	) => {
		#[test]
		fn test_subject_public_key_info_creation() {
			let test_cases = [
				$(($oid, $key_bytes)),+
			];

			for (oid, public_key_bytes) in test_cases {
				let alg_id = <$algorithm_identifier_type>::new(oid).unwrap();
				let spki = <$subject_public_key_info_type>::new(alg_id, &public_key_bytes).unwrap();
				assert_eq!(spki.subject_public_key.raw_bytes(), &public_key_bytes);
			}
		}
	};
}
/// Macro to test TryFrom conversions for AlgorithmIdentifier from OID strings
#[macro_export]
macro_rules! test_algorithm_identifier_try_from {
	(
		$algorithm_identifier_type:ty,
		valid: { $($valid_input:expr => $valid_expected:expr),+ $(,)? },
		invalid: { $($invalid_input:expr),+ $(,)? }
	) => {
		#[test]
		fn test_try_from_valid_oids() {
			$(
				// Test &str conversion
				let alg_id: $algorithm_identifier_type = $valid_input.parse().unwrap();
				assert_eq!(alg_id.algorithm.to_string(), $valid_expected);
				assert!(alg_id.parameters.is_none());

				// Test String conversion
				let oid_string = $valid_input.to_string();
				let alg_id: $algorithm_identifier_type = oid_string.parse().unwrap();
				assert_eq!(alg_id.algorithm.to_string(), $valid_expected);
				assert!(alg_id.parameters.is_none());
			)+
		}

		#[test]
		fn test_try_from_invalid_oids() {
			$(
				// Test &str conversion fails
				let result: Result<$algorithm_identifier_type, _> = $invalid_input.parse();
				assert!(result.is_err());

				// Test String conversion fails
				let oid_string = $invalid_input.to_string();
				let result: Result<$algorithm_identifier_type, _> = oid_string.parse();
				assert!(result.is_err());
			)+
		}
	};
}

/// Macro to test AlgorithmIdentifier creation with parameters
#[macro_export]
macro_rules! test_algorithm_identifier_with_params {
	(
		$algorithm_identifier_type:ty,
		$any_type:ty,
		test_oids: { $($oid:expr),+ $(,)? }
	) => {
		#[test]
		fn test_algorithm_identifier_with_params() {
			let test_oids = [$($oid),+];

			for oid in test_oids {
				// Create a dummy Any parameter (NULL in this case)
				let null_param = <$any_type>::from_der(&[0x05, 0x00]).unwrap(); // ASN.1 NULL
				let alg_id = <$algorithm_identifier_type>::new_with_params(oid, null_param.clone()).unwrap();
				assert_eq!(alg_id.algorithm.to_string(), oid);
				assert!(alg_id.parameters.is_some());
				assert_eq!(alg_id.parameters.unwrap(), null_param);
			}
		}

		#[test]
		fn test_algorithm_identifier_with_invalid_oid_in_new_with_params() {
			let null_param = <$any_type>::from_der(&[0x05, 0x00]).unwrap();
			let result = <$algorithm_identifier_type>::new_with_params("invalid.oid", null_param);
			assert!(result.is_err());
		}
	};
}

/// Macro to test SubjectPublicKeyInfo with various key sizes
#[macro_export]
macro_rules! test_subject_public_key_info_key_sizes {
	(
		$algorithm_identifier_type:ty,
		$subject_public_key_info_type:ty,
		test_oid: $test_oid:expr
	) => {
		#[test]
		fn test_subject_public_key_info_with_various_key_sizes() {
			// Test with empty key bytes
			let alg_id = <$algorithm_identifier_type>::new($test_oid).unwrap();
			let empty_key_result = <$subject_public_key_info_type>::new(alg_id.clone(), []);
			assert!(empty_key_result.is_ok()); // Empty bytes should be valid for BitString

			// Test with various key sizes
			let test_sizes = [1, 32, 64, 65, 256];
			for size in test_sizes {
				let key_bytes = vec![0x42; size];

				// Test with valid key bytes
				let spki_result = <$subject_public_key_info_type>::new(alg_id.clone(), &key_bytes);
				assert!(spki_result.is_ok());

				// Verify the created SubjectPublicKeyInfo
				let spki = spki_result.unwrap();
				assert_eq!(spki.subject_public_key.raw_bytes(), &key_bytes);
			}
		}
	};
}

/// Macro to test DER encoding/decoding round-trip
#[macro_export]
macro_rules! test_der_round_trip {
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

				let der_bytes = original.to_der().unwrap();
				assert!(!der_bytes.is_empty());

				let decoded: $struct_type = <$struct_type>::from_der(&der_bytes).unwrap();
				assert_eq!(original, decoded);
			)+
		}
	};
}

/// Get the OID JSON string from the oids.json file
#[cfg(feature = "serde")]
pub fn get_oid_json() -> String {
	include_str!("../oids.json").to_string()
}

#[cfg(all(test, feature = "serde"))]
mod tests {
	use super::*;
	use serde_json;

	// Test data constants
	const TEST_OID_STR: &str = "1.2.840.113549.1.1.1";
	const TEST_OID_JSON: &str = r#""1.2.840.113549.1.1.1""#;

	const TEST_OCTET_BYTES: &[u8] = &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
	const TEST_OCTET_JSON: &str = r#""0123456789abcdef""#;

	const TEST_BIT_BYTES: &[u8] = &[0xfe, 0xdc, 0xba, 0x98];
	const TEST_BIT_JSON: &str = r#""fedcba98""#;

	// Test OID database
	const TEST_OID_DB: &[(&str, &str)] = &[
		("RSA", "1.2.840.113549.1.1.1"),
		("SHA256", "2.16.840.1.101.3.4.2.1"),
		("Ed25519", "1.3.101.112"),
		("ECDSA_P256", "1.2.840.10045.3.1.7"),
	];

	fn get_test_oid_db() -> HashMap<&'static str, &'static str> {
		TEST_OID_DB.iter().cloned().collect()
	}

	/// Macro to test our utility functions directly
	macro_rules! test_utility_functions {
		($test_name:ident, $type:ty, $create_fn:expr, $serialize_fn:ident, $deserialize_fn:ident, $expected_json:expr) => {
			#[test]
			fn $test_name() {
				let original: $type = $create_fn;

				// Test serialization function
				let mut serialized_output = Vec::new();
				let mut serializer = serde_json::Serializer::new(&mut serialized_output);
				$serialize_fn(&original, &mut serializer).expect("serialization failed");
				let serialized = String::from_utf8(serialized_output).unwrap();
				assert_eq!(serialized, $expected_json);

				// Test deserialization function
				// Verify round-trip equality
				let mut deserializer = serde_json::Deserializer::from_str(&serialized);
				let deserialized = $deserialize_fn(&mut deserializer).expect("deserialization failed");
				assert_eq!(original, deserialized);
			}
		};
	}

	test_utility_functions!(
		test_oid_utility_functions,
		ObjectIdentifier,
		{
			#[cfg(feature = "der")]
			{
				ObjectIdentifier::new(TEST_OID_STR).unwrap()
			}
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{
				crate::utils::parse_oid_string(TEST_OID_STR).unwrap()
			}
		},
		serialize_oid,
		deserialize_oid,
		TEST_OID_JSON
	);
	test_utility_functions!(
		test_octet_string_utility_functions,
		OctetString,
		{
			#[cfg(feature = "der")]
			{
				OctetString::new(TEST_OCTET_BYTES).unwrap()
			}
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{
				OctetString::from_slice(TEST_OCTET_BYTES)
			}
		},
		serialize_octet_string,
		deserialize_octet_string,
		TEST_OCTET_JSON
	);
	test_utility_functions!(
		test_bit_string_utility_functions,
		BitString,
		{
			#[cfg(feature = "der")]
			{
				BitString::from_bytes(TEST_BIT_BYTES).unwrap()
			}
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{
				BitString::from_vec(TEST_BIT_BYTES.to_vec())
			}
		},
		serialize_bit_string,
		deserialize_bit_string,
		TEST_BIT_JSON
	);

	/// Macro to test deserialization error cases
	macro_rules! test_deserialize_error {
		($($deserialize_fn:ident: $invalid_data:expr),+ $(,)?) => {
			#[test]
			fn test_deserialize_errors() {
				$(
					let mut deserializer = serde_json::Deserializer::from_str($invalid_data);

					let result = $deserialize_fn(&mut deserializer);
					assert!(result.is_err());
				)+
			}
		};
	}

	test_deserialize_error!(
		deserialize_octet_string: r#""not_hex_data""#,
		deserialize_bit_string: r#""not_hex_data""#,
		deserialize_octet_string: r#""abc""#,
		deserialize_oid: r#""""#,
		deserialize_oid: r#""not.a.valid.oid""#,
	);

	/// Macro to test serialization output
	macro_rules! test_serialize_output {
		($($create_fn:expr, $serialize_fn:ident => $expected:expr),+ $(,)?) => {
			#[test]
			fn test_serialize_outputs() {
				$(
					let value = $create_fn;
					let mut serialized_output = Vec::new();
					let mut serializer = serde_json::Serializer::new(&mut serialized_output);
					$serialize_fn(&value, &mut serializer).unwrap();
					let serialized = String::from_utf8(serialized_output).unwrap();
					assert_eq!(serialized, $expected);
				)+
			}
		};
	}

	test_serialize_output!(
		{
			#[cfg(feature = "der")]
			{ OctetString::new([]).unwrap() }
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{ OctetString::from_slice(&[]) }
		}, serialize_octet_string => r#""""#,
		{
			#[cfg(feature = "der")]
			{ BitString::from_bytes(&[]).unwrap() }
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{ BitString::from_vec(vec![]) }
		}, serialize_bit_string => r#""""#,
		{
			#[cfg(feature = "der")]
			{ OctetString::new([0xAB, 0xCD, 0xEF]).unwrap() }
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{ OctetString::from_slice(&[0xAB, 0xCD, 0xEF]) }
		}, serialize_octet_string => r#""abcdef""#,
		{
			#[cfg(feature = "der")]
			{ BitString::from_bytes(&[0xFF, 0x00]).unwrap() }
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{ BitString::from_vec(vec![0xFF, 0x00]) }
		}, serialize_bit_string => r#""ff00""#,
		{
			#[cfg(feature = "der")]
			{ ObjectIdentifier::new("1.2.3.4.5").unwrap() }
			#[cfg(all(feature = "rasn", not(feature = "der")))]
			{ crate::utils::parse_oid_string("1.2.3.4.5").unwrap() }
		}, serialize_oid => r#""1.2.3.4.5""#,
	);

	#[test]
	fn test_oid_error_cases() {
		// Test invalid OID format
		let invalid_json = r#""invalid.oid.format""#;
		let mut deserializer = serde_json::Deserializer::from_str(invalid_json);

		let result = deserialize_oid(&mut deserializer);
		assert!(result.is_err());
	}

	#[test]
	fn test_get_oid() {
		let oid_db = get_test_oid_db();

		// Test successful lookup
		let result = get_oid("RSA", &oid_db).unwrap();
		assert_eq!(result.to_string(), "1.2.840.113549.1.1.1");

		// Test unknown algorithm
		let result = get_oid("UnknownAlgorithm", &oid_db);
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));

		// Test invalid OID format in database
		let mut invalid_oid_db = HashMap::new();
		invalid_oid_db.insert("InvalidOID", "invalid.oid.format");
		let result = get_oid("InvalidOID", &invalid_oid_db);
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_lookup_by_oid() {
		let oid_db = get_test_oid_db();

		// Test successful lookup
		let result = lookup_by_oid("1.2.840.113549.1.1.1", &oid_db).unwrap();
		assert_eq!(result, "RSA");

		// Test unknown OID (using a valid but non-existent OID)
		let result = lookup_by_oid("1.2.3.4.5.6.7", &oid_db);
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_lookup_by_object_identifier() {
		let oid_db = get_test_oid_db();

		// Test successful lookup
		#[cfg(feature = "der")]
		let oid = ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap();
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		let oid = crate::utils::parse_oid_string("1.2.840.113549.1.1.1").unwrap();

		let result = lookup_by_object_identifier(&oid, &oid_db).unwrap();
		assert_eq!(result, "RSA");

		// Test unknown OID (using a valid but non-existent OID)
		#[cfg(feature = "der")]
		let unknown_oid = ObjectIdentifier::new("1.2.3.4.5.6.7").unwrap();
		#[cfg(all(feature = "rasn", not(feature = "der")))]
		let unknown_oid = crate::utils::parse_oid_string("1.2.3.4.5.6.7").unwrap();

		let result = lookup_by_object_identifier(&unknown_oid, &oid_db);
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_parse_oid_string() {
		// Test successful parsing
		let result = parse_oid_string("1.2.840.113549.1.1.1").unwrap();
		assert_eq!(result.to_string(), "1.2.840.113549.1.1.1");

		// Test invalid OID format
		let result = parse_oid_string("invalid.oid");
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_validate_oid_format() {
		// Test successful validation
		let result = validate_oid_format("1.2.840.113549.1.1.1").unwrap();
		assert_eq!(result, vec![1, 2, 840, 113549, 1, 1, 1]);

		// Test empty string
		let result = validate_oid_format("");
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));

		// Test invalid component
		let result = validate_oid_format("1.invalid.3");
		assert!(matches!(result, Err(Asn1Error::InvalidOid { .. })));
	}

	#[test]
	fn test_get_oid_json() {
		let json_content = get_oid_json();
		assert!(!json_content.is_empty());

		// Verify it's valid JSON
		let parsed: serde_json::Value = serde_json::from_str(&json_content).unwrap();
		assert!(parsed.is_object());
	}
}
