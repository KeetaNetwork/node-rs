use crypto::HashAlgorithm;
use der::asn1::{Any, BitString, Ia5String, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Header, Reader, SliceReader, Tag, TagNumber, Tagged};

use crate::error::CertificateError;
use crate::oids;
use crate::{AttributeTypeAndValue, DistinguishedName, NameValuePair};

/// Create a Distinguished Name from name-value pairs.
///
/// This function creates an X.509 Distinguished Name from an array of
/// (OID, value) pairs where OID is a string representation and value
/// is the attribute value.
///
/// # Example
///
/// ```rust
/// use x509::utils::create_dn;
/// use x509::oids;
///
/// let pairs = &[
///     (oids::CN, "example.com"),
///     (oids::O, "Example Organization")
/// ];
///
/// let dn = create_dn(pairs).unwrap();
/// ```
pub fn create_dn(pairs: &[(&str, &str)]) -> Result<DistinguishedName, CertificateError> {
	let mut dn = Vec::new();
	for (name, value) in pairs {
		let attribute_type = ObjectIdentifier::new(name)?;
		// Create IA5String for the attribute value (commonly used in X.509)
		let ia5_string = Ia5String::new(value)?;
		let attribute_value = Any::encode_from(&ia5_string)?;

		let attr = AttributeTypeAndValue { attribute_type, attribute_value };
		let rdn = SetOfVec::from_iter(vec![attr])?;

		dn.push(rdn);
	}

	Ok(dn)
}

/// Generate a key identifier from a public key using SHA-1.
///
/// This function creates a key identifier suitable for Subject Key Identifier
/// and Authority Key Identifier extensions by hashing the public key using
/// SHA-1 as specified in RFC 5280.
///
/// # Example
///
/// ```rust
/// use x509::utils::generate_key_identifier;
/// use x509::asn1::BitString;
///
/// let public_key_bytes = &[0x04, 0x01, 0x02, 0x03]; // Example public key
/// let bit_string = BitString::new(0, public_key_bytes).unwrap();
///
/// let key_id = generate_key_identifier(&bit_string).unwrap();
/// assert_eq!(key_id.len(), 20); // SHA-1 produces 20 bytes
/// ```
pub fn generate_key_identifier(public_key: &BitString) -> Result<Vec<u8>, CertificateError> {
	let key_bytes = public_key.raw_bytes();
	let hash = HashAlgorithm::Sha1.hash(key_bytes);

	Ok(hash)
}

/// Convert a DistinguishedName to name-value pairs.
///
/// This function converts an X.509 Distinguished Name to a structured format
/// using common name mappings for well-known OIDs.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "serde")]
/// # {
/// use x509::utils::{create_dn, dn_to_name_value_pairs};
/// use x509::oids;
///
/// let pairs = &[(oids::CN, "example.com"), (oids::O, "Example Org")];
/// let dn = create_dn(pairs).unwrap();
/// let name_value_pairs = dn_to_name_value_pairs(&dn);
///
/// assert_eq!(name_value_pairs.len(), 2);
/// assert_eq!(name_value_pairs[0].name, "commonName");
/// assert_eq!(name_value_pairs[0].value, "example.com");
/// # }
/// ```
#[cfg(feature = "serde")]
pub fn dn_to_name_value_pairs(dn: &DistinguishedName) -> Vec<NameValuePair> {
	dn.iter()
		.flat_map(|rdn_set| {
			rdn_set.iter().map(|attr| {
				let name = match attr.attribute_type.to_string().as_str() {
					oids::CN => "commonName".to_string(),
					oids::C => "countryName".to_string(),
					oids::L => "localityName".to_string(),
					oids::ST => "stateOrProvinceName".to_string(),
					oids::O => "organizationName".to_string(),
					oids::OU => "organizationalUnitName".to_string(),
					oids::EMAIL_ADDRESS => "emailAddress".to_string(),
					oid => oid.to_string(),
				};
				// Try to decode as IA5String first, fall back to raw bytes if that fails
				let value = if let Ok(ia5_string) = attr.attribute_value.decode_as::<Ia5String>() {
					ia5_string.as_str().to_string()
				} else {
					// Fallback to treating as raw bytes
					String::from_utf8_lossy(attr.attribute_value.value()).to_string()
				};

				NameValuePair { name, value }
			})
		})
		.collect()
}

/// Convert name-value pairs to a DistinguishedName.
///
/// This function creates an X.509 Distinguished Name from structured name-value
/// pairs, supporting both common names (like "commonName") and OID strings.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "serde")]
/// # {
/// use x509::utils::name_value_pairs_to_dn;
/// use x509::NameValuePair;
///
/// let pairs = vec![
///     NameValuePair { name: "commonName".to_string(), value: "example.com".to_string() },
///     NameValuePair { name: "organizationName".to_string(), value: "Example Org".to_string() },
/// ];
///
/// let dn = name_value_pairs_to_dn(&pairs).unwrap();
/// assert_eq!(dn.len(), 2);
/// # }
/// ```
#[cfg(feature = "serde")]
pub fn name_value_pairs_to_dn(pairs: &[NameValuePair]) -> Result<DistinguishedName, CertificateError> {
	let mut dn = Vec::new();
	for pair in pairs {
		let attribute_type = match pair.name.as_str() {
			"commonName" | "CN" => ObjectIdentifier::new(oids::CN)?,
			"countryName" | "C" => ObjectIdentifier::new(oids::C)?,
			"localityName" | "L" => ObjectIdentifier::new(oids::L)?,
			"stateOrProvinceName" | "ST" => ObjectIdentifier::new(oids::ST)?,
			"organizationName" | "O" => ObjectIdentifier::new(oids::O)?,
			"organizationalUnitName" | "OU" => ObjectIdentifier::new(oids::OU)?,
			"emailAddress" => ObjectIdentifier::new(oids::EMAIL_ADDRESS)?,
			oid_str => ObjectIdentifier::new(oid_str)?,
		};

		let ia5_string = Ia5String::new(&pair.value)?;
		let attribute_value = Any::encode_from(&ia5_string)?;
		let attr = AttributeTypeAndValue { attribute_type, attribute_value };

		// Each attribute goes in its own RDN set for simplicity
		let rdn = SetOfVec::from_iter(vec![attr])?;
		dn.push(rdn);
	}

	Ok(dn)
}

/// Parse Subject Key Identifier from extension bytes.
///
/// This function extracts the actual key identifier from a Subject Key
/// Identifier extension by parsing the OCTET STRING ASN.1 structure using
/// proper DER decoding.
///
/// # Example
///
/// ```rust
/// use x509::utils::parse_key_identifier;
///
/// // Example OCTET STRING: tag (0x04) + length (0x14) + 20 bytes of key ID
/// let extension_bytes = &[0x04, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14];
///
/// let key_id = parse_key_identifier(extension_bytes).unwrap();
/// assert_eq!(key_id.len(), 20);
/// ```
pub fn parse_key_identifier(bytes: &[u8]) -> Option<Vec<u8>> {
	// Subject Key Identifier is an OCTET STRING
	let mut reader = SliceReader::new(bytes).ok()?;
	let octet_string = OctetString::decode(&mut reader).ok()?;

	Some(octet_string.as_bytes().to_vec())
}

/// Parse Authority Key Identifier from extension bytes.
///
/// This function extracts the key identifier from an Authority Key Identifier
/// extension by parsing the ASN.1 SEQUENCE structure and looking for the
/// [0] IMPLICIT KeyIdentifier component using proper DER decoding.
///
/// # Example
///
/// ```rust
/// use x509::utils::parse_authority_key_identifier;
///
/// // Example Authority Key Identifier: SEQUENCE + [0] IMPLICIT KeyIdentifier
/// let extension_bytes = &[0x30, 0x16, 0x80, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14];
///
/// let key_id = parse_authority_key_identifier(extension_bytes).unwrap();
/// assert_eq!(key_id.len(), 20);
/// ```
pub fn parse_authority_key_identifier(bytes: &[u8]) -> Option<Vec<u8>> {
	let mut reader = SliceReader::new(bytes).ok()?;

	// Decode the SEQUENCE header
	let sequence_header = Header::decode(&mut reader).ok()?;
	if sequence_header.tag != Tag::Sequence {
		return None;
	}

	// Check if we have enough remaining bytes for the sequence content
	let remaining_len = reader.remaining_len();
	if remaining_len < sequence_header.length {
		return None;
	}

	// Read the sequence content bytes
	let sequence_bytes = reader.read_slice(sequence_header.length).ok()?;
	let mut content_reader = SliceReader::new(sequence_bytes).ok()?;

	// Look for [0] IMPLICIT KeyIdentifier (tag 0x80)
	while !content_reader.is_finished() {
		let element = Any::decode(&mut content_reader).ok()?;

		// Check if this is a context-specific tag [0] (0x80)
		if element.tag().number() == TagNumber::N0 && element.tag().is_context_specific() {
			// For IMPLICIT tag, the content is directly the key identifier bytes
			return Some(element.value().to_vec());
		}
	}

	None
}

/// Convert a Distinguished Name to a string representation.
///
/// This function converts an X.509 Distinguished Name (DN) to a human-readable
/// string format using the format "attribute=value, attribute=value".
///
/// # Example
///
/// ```rust
/// use x509::utils::create_dn;
/// use x509::utils::dn_to_string;
/// use x509::oids;
///
/// let pairs = &[(oids::CN, "example.com"), (oids::O, "Example Org")];
/// let dn = create_dn(pairs).unwrap();
///
/// let dn_string = dn_to_string(&dn);
/// assert!(dn_string.contains("example.com"));
/// assert!(dn_string.contains("Example Org"));
/// ```
pub fn dn_to_string(dn: &DistinguishedName) -> String {
	dn.iter()
		.flat_map(|rdn| rdn.iter())
		.map(|attr| {
			// Try to decode as IA5String first, fall back to raw bytes if that fails
			let value = if let Ok(ia5_string) = attr.attribute_value.decode_as::<Ia5String>() {
				ia5_string.as_str().to_string()
			} else {
				String::from_utf8_lossy(attr.attribute_value.value()).to_string()
			};

			format!("{}={}", attr.attribute_type, value)
		})
		.collect::<Vec<_>>()
		.join(", ")
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::BitString;
	use crate::oids;
	use crate::DistinguishedName;

	#[test]
	fn test_create_dn() {
		// Test with empty pairs
		let empty_pairs: &[(&str, &str)] = &[];
		let empty_dn = create_dn(empty_pairs).unwrap();
		assert_eq!(empty_dn.len(), 0);

		// Test with single attribute
		let single_pairs = &[(oids::CN, "single.example.com")];
		let single_dn = create_dn(single_pairs).unwrap();
		assert_eq!(single_dn.len(), 1);
		assert_eq!(single_dn[0].len(), 1);
		assert_eq!(single_dn[0].get(0).unwrap().attribute_type.to_string(), oids::CN);

		// Test with multiple attributes
		let multi_pairs = &[
			(oids::CN, "example.com"),
			(oids::O, "Example Organization"),
			(oids::OU, "IT Department"),
			(oids::C, "US"),
		];
		let multi_dn = create_dn(multi_pairs).unwrap();
		assert_eq!(multi_dn.len(), 4);

		// Verify each attribute is correctly stored
		for (i, (expected_oid, expected_value)) in multi_pairs.iter().enumerate() {
			assert_eq!(multi_dn[i].len(), 1);
			assert_eq!(multi_dn[i].get(0).unwrap().attribute_type.to_string(), *expected_oid);

			let ia5_string: Ia5String = multi_dn[i].get(0).unwrap().attribute_value.decode_as().unwrap();
			assert_eq!(ia5_string.as_str(), *expected_value);
		}

		// Test with special characters
		let special_pairs = &[(oids::CN, "test with spaces"), (oids::O, "Org,with=special;chars")];
		let special_dn = create_dn(special_pairs).unwrap();
		assert_eq!(special_dn.len(), 2);

		let ia5_string1: Ia5String = special_dn[0].get(0).unwrap().attribute_value.decode_as().unwrap();
		assert_eq!(ia5_string1.as_str(), "test with spaces");

		let ia5_string2: Ia5String = special_dn[1].get(0).unwrap().attribute_value.decode_as().unwrap();
		assert_eq!(ia5_string2.as_str(), "Org,with=special;chars");

		// Test with invalid OID (should return an error)
		let invalid_pairs = &[("invalid.oid", "value")];
		let result = create_dn(invalid_pairs);
		assert!(result.is_err());
	}

	#[test]
	fn test_dn_to_string() {
		// Test with empty DN
		let empty_dn: DistinguishedName = Vec::new();
		let empty_string = dn_to_string(&empty_dn);
		assert_eq!(empty_string, "");

		// Test with single attribute
		let single_pairs = &[(oids::CN, "single.example.com")];
		let single_dn = create_dn(single_pairs).unwrap();
		let single_string = dn_to_string(&single_dn);
		assert_eq!(single_string, "2.5.4.3=single.example.com");
		assert!(!single_string.contains(", ")); // No comma for single attribute

		// Test with multiple common DN attributes
		let multi_pairs = &[
			(oids::CN, "example.com"),
			(oids::O, "Example Organization"),
			(oids::OU, "IT Department"),
			(oids::C, "US"),
		];

		// Verify all components are present
		let multi_dn = create_dn(multi_pairs).unwrap();
		let multi_string = dn_to_string(&multi_dn);
		assert!(multi_string.contains("example.com"));
		assert!(multi_string.contains("Example Organization"));
		assert!(multi_string.contains("IT Department"));
		assert!(multi_string.contains("US"));
		assert!(multi_string.contains("2.5.4.3=")); // CN OID
		assert!(multi_string.contains("2.5.4.10=")); // O OID
		assert!(multi_string.contains(", ")); // Comma-separated format

		// Test with special characters in values
		let special_pairs = &[(oids::CN, "test with spaces"), (oids::O, "Org,with=special;chars")];
		let special_dn = create_dn(special_pairs).unwrap();
		let special_string = super::dn_to_string(&special_dn);
		assert!(special_string.contains("test with spaces"));
		assert!(special_string.contains("Org,with=special;chars"));
		assert!(special_string.contains(", ")); // Should still be comma-separated
	}

	#[test]
	fn test_generate_key_identifier() {
		// Test with basic public key data
		// Should be exactly 20 bytes (SHA-1 output)
		let public_key_bytes = &[0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
		let bit_string = BitString::new(0, public_key_bytes).unwrap();
		let key_id = generate_key_identifier(&bit_string).unwrap();
		assert_eq!(key_id.len(), 20);

		// Test with different public key data should produce different result
		let public_key_bytes = &[0x04, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
		let bit_string = BitString::new(0, public_key_bytes).unwrap();
		let key_id2 = generate_key_identifier(&bit_string).unwrap();
		assert_eq!(key_id2.len(), 20);
		// Different inputs should produce different outputs
		assert_ne!(key_id, key_id2);

		// Test with empty public key
		let empty_key = BitString::new(0, []).unwrap();
		let empty_key_id = generate_key_identifier(&empty_key).unwrap();
		assert_eq!(empty_key_id.len(), 20);
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_dn_to_name_value_pairs() {
		// Test with empty DN
		let empty_dn: DistinguishedName = Vec::new();
		let empty_pairs = dn_to_name_value_pairs(&empty_dn);
		assert_eq!(empty_pairs.len(), 0);

		// Test with single attribute
		let single_dn_pairs = &[(oids::CN, "example.com")];
		let single_dn = create_dn(single_dn_pairs).unwrap();
		let single_pairs = dn_to_name_value_pairs(&single_dn);
		assert_eq!(single_pairs.len(), 1);
		assert_eq!(single_pairs[0].name, "commonName");
		assert_eq!(single_pairs[0].value, "example.com");

		// Test with multiple common attributes
		let multi_dn_pairs = &[
			(oids::CN, "example.com"),
			(oids::O, "Example Organization"),
			(oids::OU, "IT Department"),
			(oids::C, "US"),
			(oids::L, "San Francisco"),
			(oids::ST, "California"),
			(oids::EMAIL_ADDRESS, "admin@example.com"), // Email
		];
		let multi_dn = create_dn(multi_dn_pairs).unwrap();
		let multi_pairs = dn_to_name_value_pairs(&multi_dn);
		assert_eq!(multi_pairs.len(), 7);

		// Verify each mapping
		let expected_mappings = vec![
			("commonName", "example.com"),
			("organizationName", "Example Organization"),
			("organizationalUnitName", "IT Department"),
			("countryName", "US"),
			("localityName", "San Francisco"),
			("stateOrProvinceName", "California"),
			("emailAddress", "admin@example.com"),
		];

		// Check each expected mapping
		for (i, (expected_name, expected_value)) in expected_mappings.iter().enumerate() {
			assert_eq!(multi_pairs[i].name, *expected_name);
			assert_eq!(multi_pairs[i].value, *expected_value);
		}

		// Test with unknown OID (should keep original OID string)
		let unknown_oid_pairs = &[("1.2.3.4.5", "unknown_value")];
		let unknown_dn = create_dn(unknown_oid_pairs).unwrap();
		let unknown_pairs = dn_to_name_value_pairs(&unknown_dn);
		assert_eq!(unknown_pairs.len(), 1);
		assert_eq!(unknown_pairs[0].name, "1.2.3.4.5");
		assert_eq!(unknown_pairs[0].value, "unknown_value");
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_name_value_pairs_to_dn() {
		// Test with empty pairs
		let empty_pairs: Vec<NameValuePair> = vec![];
		let empty_dn = name_value_pairs_to_dn(&empty_pairs).unwrap();
		assert_eq!(empty_dn.len(), 0);

		// Test with single pair using common name
		let single_pairs = vec![NameValuePair { name: "commonName".to_string(), value: "example.com".to_string() }];
		let single_dn = name_value_pairs_to_dn(&single_pairs).unwrap();
		assert_eq!(single_dn.len(), 1);
		assert_eq!(single_dn[0].len(), 1);
		assert_eq!(single_dn[0].get(0).unwrap().attribute_type.to_string(), oids::CN);
		let ia5_string: Ia5String = single_dn[0].get(0).unwrap().attribute_value.decode_as().unwrap();
		assert_eq!(ia5_string.as_str(), "example.com");

		// Test with multiple pairs using both common names and short forms
		let multi_pairs = vec![
			NameValuePair { name: "commonName".to_string(), value: "example.com".to_string() },
			NameValuePair { name: "O".to_string(), value: "Example Org".to_string() },
			NameValuePair { name: "organizationalUnitName".to_string(), value: "IT Dept".to_string() },
			NameValuePair { name: "C".to_string(), value: "US".to_string() },
			NameValuePair { name: "localityName".to_string(), value: "SF".to_string() },
			NameValuePair { name: "ST".to_string(), value: "CA".to_string() },
			NameValuePair { name: "emailAddress".to_string(), value: "admin@example.com".to_string() },
		];

		let multi_dn = name_value_pairs_to_dn(&multi_pairs).unwrap();
		assert_eq!(multi_dn.len(), 7);

		// Verify each attribute
		let expected = [
			(oids::CN, "example.com"),
			(oids::O, "Example Org"),
			(oids::OU, "IT Dept"),
			(oids::C, "US"),
			(oids::L, "SF"),
			(oids::ST, "CA"),
			(oids::EMAIL_ADDRESS, "admin@example.com"),
		];
		for (i, (expected_oid, expected_value)) in expected.iter().enumerate() {
			assert_eq!(multi_dn[i].len(), 1);
			assert_eq!(multi_dn[i].get(0).unwrap().attribute_type.to_string(), *expected_oid);
			let ia5_string: Ia5String = multi_dn[i].get(0).unwrap().attribute_value.decode_as().unwrap();
			assert_eq!(ia5_string.as_str(), *expected_value);
		}

		// Test with direct OID
		let oid_pairs = vec![NameValuePair { name: oids::CN.to_string(), value: "direct_oid.com".to_string() }];
		let oid_dn = name_value_pairs_to_dn(&oid_pairs).unwrap();
		assert_eq!(oid_dn.len(), 1);
		assert_eq!(oid_dn[0].get(0).unwrap().attribute_type.to_string(), oids::CN);
		let ia5_string: Ia5String = oid_dn[0].get(0).unwrap().attribute_value.decode_as().unwrap();
		assert_eq!(ia5_string.as_str(), "direct_oid.com");

		// Test with invalid OID
		let invalid_pairs = vec![NameValuePair { name: "invalid.oid".to_string(), value: "value".to_string() }];
		let result = name_value_pairs_to_dn(&invalid_pairs);
		assert!(result.is_err());
	}

	#[test]
	#[cfg(feature = "serde")]
	fn test_dn_roundtrip() {
		// Test roundtrip conversion: DN -> name-value pairs -> DN
		let original_pairs = &[
			(oids::CN, "example.com"),
			(oids::O, "Example Organization"),
			(oids::OU, "IT Department"),
			(oids::C, "US"),
		];

		// Should have same number of attributes
		let original_dn = create_dn(original_pairs).unwrap();
		let name_value_pairs = dn_to_name_value_pairs(&original_dn);
		let reconstructed_dn = name_value_pairs_to_dn(&name_value_pairs).unwrap();
		assert_eq!(original_dn.len(), reconstructed_dn.len());

		// Each attribute should match
		for (original_rdn, reconstructed_rdn) in original_dn.iter().zip(reconstructed_dn.iter()) {
			assert_eq!(original_rdn.len(), reconstructed_rdn.len());
			for (original_attr, reconstructed_attr) in original_rdn.iter().zip(reconstructed_rdn.iter()) {
				assert_eq!(original_attr.attribute_type, reconstructed_attr.attribute_type);
				assert_eq!(original_attr.attribute_value.value(), reconstructed_attr.attribute_value.value());
			}
		}
	}

	#[test]
	fn test_parse_key_identifier() {
		// Test valid OCTET STRING
		let valid_bytes = &[
			0x04, 0x14, // OCTET STRING, length 20
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14,
		];

		let key_id = parse_key_identifier(valid_bytes).unwrap();
		assert_eq!(key_id.len(), 20);
		assert_eq!(
			key_id,
			&[
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
				0x12, 0x13, 0x14
			]
		);

		// Test with different length
		let short_bytes = &[0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];
		let short_key_id = parse_key_identifier(short_bytes).unwrap();
		assert_eq!(short_key_id.len(), 4);
		assert_eq!(short_key_id, &[0xAA, 0xBB, 0xCC, 0xDD]);

		// Test with empty key identifier
		let empty_bytes = &[0x04, 0x00];
		let empty_key_id = parse_key_identifier(empty_bytes).unwrap();
		assert_eq!(empty_key_id.len(), 0);

		// Test invalid cases

		// Wrong tag (not OCTET STRING)
		let wrong_tag = &[0x05, 0x04, 0x01, 0x02, 0x03, 0x04];
		assert!(parse_key_identifier(wrong_tag).is_none());

		// Too short (missing length)
		let too_short = &[0x04];
		assert!(parse_key_identifier(too_short).is_none());

		// Length longer than remaining bytes
		let bad_length = &[0x04, 0x10, 0x01, 0x02]; // Claims 16 bytes but only has 2
		assert!(parse_key_identifier(bad_length).is_none());

		// Empty input
		let empty_input = &[];
		assert!(parse_key_identifier(empty_input).is_none());
	}

	#[test]
	fn test_parse_authority_key_identifier() {
		// Test valid Authority Key Identifier with [0] KeyIdentifier
		let valid_bytes = &[
			0x30, 0x16, // SEQUENCE, length 22
			0x80, 0x14, // [0] IMPLICIT, length 20
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14,
		];

		let key_id = parse_authority_key_identifier(valid_bytes).unwrap();
		assert_eq!(key_id.len(), 20);
		assert_eq!(
			key_id,
			&[
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
				0x12, 0x13, 0x14
			]
		);

		// Test with shorter key identifier
		let short_bytes = &[
			0x30, 0x06, // SEQUENCE, length 6
			0x80, 0x04, // [0] IMPLICIT, length 4
			0xAA, 0xBB, 0xCC, 0xDD,
		];

		let short_key_id = parse_authority_key_identifier(short_bytes).unwrap();
		assert_eq!(short_key_id.len(), 4);
		assert_eq!(short_key_id, &[0xAA, 0xBB, 0xCC, 0xDD]);

		// Test with empty key identifier
		let empty_key_bytes = &[
			0x30, 0x02, // SEQUENCE, length 2
			0x80, 0x00, // [0] IMPLICIT, length 0
		];

		let empty_key_id = parse_authority_key_identifier(empty_key_bytes).unwrap();
		assert_eq!(empty_key_id.len(), 0);

		// Test invalid cases

		// Wrong tag (not SEQUENCE)
		let wrong_tag = &[0x04, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04];
		assert!(parse_authority_key_identifier(wrong_tag).is_none());

		// No [0] tag inside SEQUENCE
		let no_key_id = &[0x30, 0x02, 0x81, 0x00]; // [1] instead of [0]
		assert!(parse_authority_key_identifier(no_key_id).is_none());

		// Too short for SEQUENCE
		let too_short = &[0x30, 0x16, 0x80]; // Missing length and data
		assert!(parse_authority_key_identifier(too_short).is_none());

		// Length mismatch
		let bad_length = &[0x30, 0x06, 0x80, 0x10, 0x01, 0x02]; // Claims 16 bytes but only has 2
		assert!(parse_authority_key_identifier(bad_length).is_none());

		// Empty input
		let empty_input = &[];
		assert!(parse_authority_key_identifier(empty_input).is_none());

		// SEQUENCE but too short for proper parsing
		let short_sequence = &[0x30, 0x01, 0x80];
		assert!(parse_authority_key_identifier(short_sequence).is_none());
	}
}
