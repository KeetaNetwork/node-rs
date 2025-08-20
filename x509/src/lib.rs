//! X.509 certificate handling module
//!
//! This module provides functionality for creating, parsing, signing, and
//! validating X.509 certificates.

use der::asn1::ObjectIdentifier;
use der::asn1::{Any, SetOfVec};
use der::Sequence;

pub mod builder;
pub mod certificates;
pub mod error;
pub mod oids;
pub mod time;
pub mod utils;

#[cfg(feature = "serde")]
pub mod serde;
#[cfg(test)]
pub mod testing;

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
				Ok(self
					.attribute_value
					.value()
					.cmp(other.attribute_value.value()))
			}
			other => Ok(other),
		}
	}
}

#[cfg(test)]
mod tests {
	use core::cmp::Ordering;

	use asn1::Ia5String;
	use asn1::{Decode, Encode, ValueOrd};

	use super::*;

	#[test]
	fn test_attribute_value_variants() {
		macro_rules! test_attribute_value_variant {
			($variant:ident, $value:expr) => {
				let value = AttributeValue::$variant($value.to_string());
				let cloned = value.clone();
				assert_eq!(value, cloned);

				let debug_str = format!("{value:?}");
				assert!(debug_str.contains(stringify!($variant)));
				assert!(debug_str.contains($value));
			};
		}

		test_attribute_value_variant!(PrintableString, "printable");
		test_attribute_value_variant!(Utf8String, "utf8");
		test_attribute_value_variant!(T61String, "t61");
		test_attribute_value_variant!(BmpString, "bmp");
		test_attribute_value_variant!(UniversalString, "universal");
		test_attribute_value_variant!(IA5String, "ia5");
		test_attribute_value_variant!(NumericString, "123");
	}

	#[test]
	fn test_attribute_value_inequality() {
		let value1 = AttributeValue::PrintableString("test".to_string());
		let value2 = AttributeValue::Utf8String("test".to_string());
		assert_ne!(value1, value2);
	}

	#[test]
	fn test_attribute_type_and_value_value_ord() {
		macro_rules! test_value_ord_case {
			($oid1:expr, $value1:expr, $oid2:expr, $value2:expr, $expected:expr) => {
				let ia5_string1 = Ia5String::new($value1).unwrap();
				let ia5_string2 = Ia5String::new($value2).unwrap();

				let attribute_type = ObjectIdentifier::new($oid1).unwrap();
				let attribute_value = Any::encode_from(&ia5_string1).unwrap();
				let attr1 = AttributeTypeAndValue { attribute_type, attribute_value };

				let attribute_type = ObjectIdentifier::new($oid2).unwrap();
				let attribute_value = Any::encode_from(&ia5_string2).unwrap();
				let attr2 = AttributeTypeAndValue { attribute_type, attribute_value };

				let result = attr1.value_cmp(&attr2).unwrap();
				assert_eq!(result, $expected);
			};
		}

		test_value_ord_case!("1.2.3.4", "value1", "1.2.3.5", "value1", Ordering::Less);
		test_value_ord_case!("1.2.3.4", "value1", "1.2.3.4", "value2", Ordering::Less);
		test_value_ord_case!("1.2.3.4", "value1", "1.2.3.4", "value1", Ordering::Equal);
		test_value_ord_case!("1.2.3.5", "value1", "1.2.3.4", "value1", Ordering::Greater);
	}

	#[test]
	fn test_attribute_type_and_value_self_comparison() {
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new("value").unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };

		let result = attr.value_cmp(&attr).unwrap();
		assert_eq!(result, Ordering::Equal);
	}

	#[test]
	fn test_attribute_type_and_value_creation() {
		macro_rules! test_attribute_creation {
			($oid:expr, $value_bytes:expr) => {
				let attribute_type = ObjectIdentifier::new($oid).unwrap();
				let value_str = core::str::from_utf8($value_bytes).unwrap();
				let ia5_string = Ia5String::new(value_str).unwrap();
				let attribute_value = Any::encode_from(&ia5_string).unwrap();
				let attr = AttributeTypeAndValue { attribute_type, attribute_value: attribute_value.clone() };

				assert_eq!(attr.attribute_type.to_string(), $oid);

				let decoded_ia5: Ia5String = attr.attribute_value.decode_as().unwrap();
				assert_eq!(decoded_ia5.as_str(), value_str);
				assert_eq!(attr.attribute_value.value(), attribute_value.value());

				let cloned = attr.clone();
				assert_eq!(attr, cloned);

				let der_bytes = attr.to_der().unwrap();
				assert!(!der_bytes.is_empty());

				let decoded = AttributeTypeAndValue::from_der(&der_bytes).unwrap();
				assert_eq!(attr, decoded);

				let debug_str = format!("{attr:?}");
				assert!(debug_str.contains("AttributeTypeAndValue"));
			};
		}

		test_attribute_creation!("1.2.3.4", b"basic value");
		test_attribute_creation!("2.5.4.3", b"Common Name");
		test_attribute_creation!("1.2.840.113549.1.9.1", b"test@example.com");
		test_attribute_creation!("2.16.840.1.101.3.4.2.1", b"");
	}

	#[test]
	fn test_attribute_type_and_value_inequality() {
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new("value").unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value: attribute_value.clone() };

		let different_oid = ObjectIdentifier::new("1.2.3.5").unwrap();
		let different_attr = AttributeTypeAndValue { attribute_type: different_oid, attribute_value };
		assert_ne!(attr, different_attr);
	}

	#[test]
	fn test_attribute_type_and_value_large_value() {
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

		// Test self equality
		assert_eq!(attr, attr);
	}

	#[test]
	fn test_distinguished_name_single_rdn() {
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string = Ia5String::new("test").unwrap();
		let attribute_value = Any::encode_from(&ia5_string).unwrap();
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };
		let rdn = SetOfVec::from_iter([attr.clone()]).unwrap();

		let dn: DistinguishedName = vec![rdn];
		assert_eq!(dn.len(), 1);
		assert_eq!(dn[0].len(), 1);
		assert_eq!(*dn[0].get(0).unwrap(), attr);
	}

	#[test]
	fn test_distinguished_name_multiple_rdn() {
		let attribute_type = ObjectIdentifier::new("1.2.3.4").unwrap();
		let ia5_string1 = Ia5String::new("test").unwrap();
		let attribute_value = Any::encode_from(&ia5_string1).unwrap();
		let attr1 = AttributeTypeAndValue { attribute_type, attribute_value };

		let attribute_type = ObjectIdentifier::new("2.5.4.3").unwrap();
		let ia5_string2 = Ia5String::new("CN=Test").unwrap();
		let attribute_value = Any::encode_from(&ia5_string2).unwrap();
		let attr2 = AttributeTypeAndValue { attribute_type, attribute_value };

		let rdn1 = SetOfVec::from_iter([attr1.clone()]).unwrap();
		let rdn2 = SetOfVec::from_iter([attr2.clone()]).unwrap();

		let multi_dn: DistinguishedName = vec![rdn1, rdn2];
		assert_eq!(multi_dn.len(), 2);
		assert_eq!(*multi_dn[0].get(0).unwrap(), attr1);
		assert_eq!(*multi_dn[1].get(0).unwrap(), attr2);
	}
}
