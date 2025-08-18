//! Utilities for working with ASN.1 types

use std::collections::HashMap;

use crate::{error::Asn1Error, ObjectIdentifier};

#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
use crate::{BitString, OctetString};

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

/// Get an OID string by algorithm name from an OID database
pub fn get_oid(name: &str, oid_db: &HashMap<&str, &str>) -> Result<ObjectIdentifier, Asn1Error> {
	let oid_str = oid_db
		.get(name)
		.ok_or_else(|| Asn1Error::InvalidOid { reason: format!("Unknown algorithm: {name}") })?;

	ObjectIdentifier::new(oid_str)
		.map_err(|_| Asn1Error::InvalidOid { reason: format!("Invalid OID format for algorithm {name}: {oid_str}") })
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
	ObjectIdentifier::new(oid_str)
		.map_err(|_| Asn1Error::InvalidOid { reason: format!("Invalid OID format: {oid_str}") })
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
		let oid = ObjectIdentifier::new("1.2.840.113549.1.1.1").unwrap();
		let result = lookup_by_object_identifier(&oid, &oid_db).unwrap();
		assert_eq!(result, "RSA");

		// Test unknown OID (using a valid but non-existent OID)
		let unknown_oid = ObjectIdentifier::new("1.2.3.4.5.6.7").unwrap();
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
}
