//! X.509 certificate handling module
//!
//! This module provides functionality for creating, parsing, signing, and
//! validating X.509 certificates.

use der::asn1::ObjectIdentifier;
use der::asn1::{Any, SetOfVec};
use der::Sequence;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod asn1;
pub mod certificates;
pub mod error;
pub mod oids;
pub mod time;
pub mod utils;

/// Relative Distinguished Name (SET OF AttributeTypeAndValue)
/// This represents a single RDN component in an X.509 Distinguished Name
pub type RelativeDistinguishedName = SetOfVec<AttributeTypeAndValue>;

/// Distinguished Name (SEQUENCE OF RelativeDistinguishedName)
/// This follows RFC 5280 X.509 standard DER encoding:
/// - DistinguishedName = SEQUENCE OF RelativeDistinguishedName
/// - RelativeDistinguishedName = SET OF AttributeTypeAndValue
pub type DistinguishedName = Vec<RelativeDistinguishedName>;

/// Attribute value in Distinguished Names
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
	PrintableString(String),
	Utf8String(String),
	T61String(String),
	BmpString(String),
	UniversalString(String),
	IA5String(String),
	NumericString(String),
}

/// Attribute type and value pair
/// Coverage: `Sequence` generated code causes false negative.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Sequence)]
pub struct AttributeTypeAndValue {
	pub attribute_type: ObjectIdentifier,
	pub attribute_value: Any,
}

impl der::ValueOrd for AttributeTypeAndValue {
	fn value_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
		// First compare by attribute type (OID)
		match self.attribute_type.value_cmp(&other.attribute_type)? {
			core::cmp::Ordering::Equal => {
				// If OIDs are equal, compare by the raw bytes of the Any value
				// The Any value already contains the properly encoded DER bytes
				Ok(self.attribute_value.value().cmp(other.attribute_value.value()))
			}
			other => Ok(other),
		}
	}
}

/// Name-value pair for Distinguished Names
#[cfg(feature = "serde")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameValuePair {
	pub name: String,
	pub value: String,
}

#[cfg(test)]
mod tests {
	use core::cmp::Ordering;

	use der::{Decode, Encode, ValueOrd};

	use super::*;
	use crate::asn1::Ia5String;

	#[test]
	fn test_attribute_value() {
		let value1 = AttributeValue::PrintableString("test".to_string());
		let value2 = value1.clone();
		assert_eq!(value1, value2);

		let value3 = AttributeValue::Utf8String("test".to_string());
		assert_ne!(value1, value3);

		let value = AttributeValue::PrintableString("test".to_string());
		let debug_str = format!("{value:?}");
		assert!(debug_str.contains("PrintableString"));
		assert!(debug_str.contains("test"));

		// Test all variants
		let variants = [
			AttributeValue::PrintableString("printable".to_string()),
			AttributeValue::Utf8String("utf8".to_string()),
			AttributeValue::T61String("t61".to_string()),
			AttributeValue::BmpString("bmp".to_string()),
			AttributeValue::UniversalString("universal".to_string()),
			AttributeValue::IA5String("ia5".to_string()),
			AttributeValue::NumericString("123".to_string()),
		];

		for variant in &variants {
			let cloned = variant.clone();
			assert_eq!(variant, &cloned);

			let debug_str = format!("{variant:?}");
			assert!(!debug_str.is_empty());
		}
	}

	#[test]
	fn test_attribute_type_and_value_value_ord() {
		let test_cases = [
			("1.2.3.4", "value1", "1.2.3.5", "value1", Ordering::Less),
			("1.2.3.4", "value1", "1.2.3.4", "value2", Ordering::Less),
			("1.2.3.4", "value1", "1.2.3.4", "value1", Ordering::Equal),
			("1.2.3.5", "value1", "1.2.3.4", "value1", Ordering::Greater),
		];

		for (oid1_str, value1_str, oid2_str, value2_str, expected) in test_cases {
			let oid1 = ObjectIdentifier::new(oid1_str).unwrap();
			let oid2 = ObjectIdentifier::new(oid2_str).unwrap();

			let ia5_string1 = Ia5String::new(value1_str).unwrap();
			let ia5_string2 = Ia5String::new(value2_str).unwrap();

			let attribute_value = Any::encode_from(&ia5_string1).unwrap();
			let attr1 = AttributeTypeAndValue { attribute_type: oid1, attribute_value };
			let attribute_value = Any::encode_from(&ia5_string2).unwrap();
			let attr2 = AttributeTypeAndValue { attribute_type: oid2, attribute_value };

			let result = attr1.value_cmp(&attr2).unwrap();
			assert_eq!(result, expected);
		}

		// Test self-comparison
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new("value").unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };

		let result = attr.value_cmp(&attr).unwrap();
		assert_eq!(result, Ordering::Equal);
	}

	#[test]
	fn test_attribute_type_and_value() {
		let test_cases: &[(&str, &[u8])] = &[
			("1.2.3.4", b"basic value"),
			("2.5.4.3", b"Common Name"),
			("1.2.840.113549.1.9.1", b"test@example.com"),
			("2.16.840.1.101.3.4.2.1", b""), // Empty value
		];

		for (oid_str, value_bytes) in test_cases {
			let attribute_type = ObjectIdentifier::new(oid_str).unwrap();
			let value_str = core::str::from_utf8(value_bytes).unwrap();
			let ia5_string = Ia5String::new(value_str).unwrap();
			let attribute_value = Any::encode_from(&ia5_string).unwrap();
			let attr = AttributeTypeAndValue { attribute_type, attribute_value: attribute_value.clone() };

			// Test creation and field access
			assert_eq!(attr.attribute_type.to_string(), *oid_str);
			let decoded_ia5: Ia5String = attr.attribute_value.decode_as().unwrap();
			assert_eq!(decoded_ia5.as_str(), value_str);
			assert_eq!(attr.attribute_value.value(), attribute_value.value());

			// Test clone and equality
			let cloned = attr.clone();
			assert_eq!(attr, cloned);

			// Test inequality with different OID
			let attribute_type = ObjectIdentifier::new("1.2.3.5").unwrap();
			let different_attr = AttributeTypeAndValue { attribute_type, attribute_value };
			assert_ne!(attr, different_attr);

			// Test DER encoding/decoding roundtrip
			let der_bytes = attr.to_der().unwrap();
			assert!(!der_bytes.is_empty());

			let decoded = AttributeTypeAndValue::from_der(&der_bytes).unwrap();
			assert_eq!(attr, decoded);

			// Test debug formatting
			let debug_str = format!("{attr:?}");
			assert!(debug_str.contains("AttributeTypeAndValue"));
		}

		// Test with large value - use a valid string for IA5String
		let large_value = "x".repeat(100);
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new(&large_value).unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };

		let der_bytes = attr.to_der().unwrap();
		let decoded = AttributeTypeAndValue::from_der(&der_bytes).unwrap();
		assert_eq!(attr, decoded);

		let decoded_ia5: Ia5String = attr.attribute_value.decode_as().unwrap();
		assert_eq!(decoded_ia5.as_str().len(), 100);

		// Test equality trait
		assert_eq!(attr, attr);
		assert!(attr == attr);
	}

	#[test]
	fn test_distinguished_name() {
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new("test").unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };

		// Create a DN with one RDN containing one attribute
		let rdn = SetOfVec::from_iter([attr.clone()]).unwrap();
		let dn: DistinguishedName = vec![rdn];
		assert_eq!(dn.len(), 1);
		assert_eq!(dn[0].len(), 1);
		assert_eq!(*dn[0].get(0).unwrap(), attr);

		// Test empty DN
		let empty_dn: DistinguishedName = Vec::new();
		assert!(empty_dn.is_empty());

		// Test DN with multiple RDNs
		let attribute_type = ObjectIdentifier::new("2.5.4.3").unwrap();
		let ia5_string2 = Ia5String::new("CN=Test").unwrap();
		let attribute_value = Any::encode_from(&ia5_string2).unwrap();
		let attr2 = AttributeTypeAndValue { attribute_type, attribute_value };
		let rdn1 = SetOfVec::from_iter([attr.clone()]).unwrap();
		let rdn2 = SetOfVec::from_iter([attr2.clone()]).unwrap();
		let multi_dn: DistinguishedName = vec![rdn1, rdn2];
		assert_eq!(multi_dn.len(), 2);
		assert_eq!(*multi_dn[0].get(0).unwrap(), attr);
		assert_eq!(*multi_dn[1].get(0).unwrap(), attr2);
	}

	#[cfg(feature = "serde")]
	#[test]
	fn test_name_value_pair() {
		let name = "commonName".to_string();
		let value = "Test Certificate".to_string();
		let pair = NameValuePair { name, value };

		// Test clone
		let cloned = pair.clone();
		assert_eq!(pair.name, cloned.name);
		assert_eq!(pair.value, cloned.value);

		// Test debug formatting
		let debug_str = format!("{pair:?}");
		assert!(debug_str.contains("NameValuePair"));
		assert!(debug_str.contains("commonName"));
		assert!(debug_str.contains("Test Certificate"));

		// Test field access
		assert_eq!(pair.name, "commonName");
		assert_eq!(pair.value, "Test Certificate");
	}
}
