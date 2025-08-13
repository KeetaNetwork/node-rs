//! Utilities for working with ASN.1 types

#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
use crate::{BitString, ObjectIdentifier, OctetString};

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

	ObjectIdentifier::new(&s).map_err(serde::de::Error::custom)
}

/// Serialize an OctetString
#[cfg(feature = "serde")]
pub fn serialize_octet_string<S>(octet_string: &OctetString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&hex::encode(octet_string.as_bytes()))
}

/// Deserialize an OctetString
#[cfg(feature = "serde")]
pub fn deserialize_octet_string<'de, D>(deserializer: D) -> Result<OctetString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

	OctetString::new(&*bytes).map_err(serde::de::Error::custom)
}

/// Serialize a BitString
#[cfg(feature = "serde")]
pub fn serialize_bit_string<S>(bit_string: &BitString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&hex::encode(bit_string.raw_bytes()))
}

/// Deserialize a BitString
#[cfg(feature = "serde")]
pub fn deserialize_bit_string<'de, D>(deserializer: D) -> Result<BitString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;

	BitString::from_bytes(&bytes).map_err(serde::de::Error::custom)
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
		ObjectIdentifier::new(TEST_OID_STR).unwrap(),
		serialize_oid,
		deserialize_oid,
		TEST_OID_JSON
	);
	test_utility_functions!(
		test_octet_string_utility_functions,
		OctetString,
		OctetString::new(TEST_OCTET_BYTES).unwrap(),
		serialize_octet_string,
		deserialize_octet_string,
		TEST_OCTET_JSON
	);
	test_utility_functions!(
		test_bit_string_utility_functions,
		BitString,
		BitString::from_bytes(TEST_BIT_BYTES).unwrap(),
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
		OctetString::new([]).unwrap(), serialize_octet_string => r#""""#,
		BitString::from_bytes(&[]).unwrap(), serialize_bit_string => r#""""#,
		OctetString::new([0xAB, 0xCD, 0xEF]).unwrap(), serialize_octet_string => r#""abcdef""#,
		BitString::from_bytes(&[0xFF, 0x00]).unwrap(), serialize_bit_string => r#""ff00""#,
		ObjectIdentifier::new("1.2.3.4.5").unwrap(), serialize_oid => r#""1.2.3.4.5""#,
	);

	#[test]
	fn test_oid_error_cases() {
		// Test invalid OID format
		let invalid_json = r#""invalid.oid.format""#;
		let mut deserializer = serde_json::Deserializer::from_str(invalid_json);

		let result = deserialize_oid(&mut deserializer);
		assert!(result.is_err());
	}
}
