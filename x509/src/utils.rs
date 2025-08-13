use asn1::{Any, BitString, Ia5String, ObjectIdentifier, OctetString, SetOfVec};
use asn1::{Decode, Header, Reader, SliceReader, Tag, TagNumber, Tagged};
use crypto::prelude::{
	CryptoVerifierWithOptions, Ed25519PublicKey, Ed25519Signature, HashAlgorithm, Secp256k1PublicKey,
	Secp256k1Signature, Secp256r1PublicKey, Secp256r1Signature, SigningOptions,
};
use crypto::utils::parse_der_ecdsa_signature;

use crate::error::CertificateError;
use crate::{AttributeTypeAndValue, DistinguishedName};

#[cfg(feature = "serde")]
use crate::oids;
#[cfg(feature = "serde")]
use crate::NameValuePair;

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
/// use asn1::oids;
///
/// let pairs = &[
///     (oids::CN, "example.com"),
///     (oids::O, "Example Organization")
/// ];
///
/// let dn = create_dn(pairs).unwrap();
/// ```
pub fn create_dn<S1: AsRef<str>, S2: AsRef<str>>(pairs: &[(S1, S2)]) -> Result<DistinguishedName, CertificateError> {
	let mut dn = Vec::new();
	for (name, value) in pairs {
		let attribute_type = ObjectIdentifier::new(name.as_ref())?;
		// Create IA5String for the attribute value (commonly used in X.509)
		let ia5_string = Ia5String::new(value.as_ref())?;
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
/// use asn1::BitString;
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
/// use asn1::oids;
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
pub fn parse_key_identifier(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
	// Subject Key Identifier is an OCTET STRING
	let mut reader = SliceReader::new(bytes.as_ref()).ok()?;
	let octet_string = OctetString::decode(&mut reader).ok()?;

	Some(octet_string.as_bytes().to_vec())
}

/// Parse Authority Key Identifier from extension bytes.
///
/// This function extracts the key identifier from an Authority Key Identifier
/// extension by parsing the ASN.1 SEQUENCE structure and looking for the
/// \[0\] IMPLICIT KeyIdentifier component using proper DER decoding.
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
pub fn parse_authority_key_identifier(bytes: impl AsRef<[u8]>) -> Option<Vec<u8>> {
	let mut reader = SliceReader::new(bytes.as_ref()).ok()?;

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
/// use asn1::oids;
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

/// Helper function to parse DER length encoding.
/// Returns (content_length, header_length) if successful.
///
/// # Example
///
/// ```rust
/// use x509::utils::parse_der_length;
///
/// // Short form: SEQUENCE with 5 bytes of content
/// let short_form = &[0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
/// let (content_len, header_len) = parse_der_length(short_form).unwrap();
/// assert_eq!(content_len, 5);
/// assert_eq!(header_len, 2);
///
/// // Long form: SEQUENCE with 256 bytes of content
/// let long_form = &[0x30, 0x82, 0x01, 0x00]; // 0x82 = long form with 2 bytes, 0x0100 = 256
/// let (content_len, header_len) = parse_der_length(long_form).unwrap();
/// assert_eq!(content_len, 256);
/// assert_eq!(header_len, 4);
/// ```
pub fn parse_der_length(data: impl AsRef<[u8]>) -> Option<(usize, usize)> {
	let data = data.as_ref();
	if data.is_empty() {
		return None;
	}

	// Skip the tag byte (should be 0x30 for SEQUENCE)
	if data[0] != 0x30 {
		return None;
	}

	if data.len() < 2 {
		return None;
	}

	let length_byte = data[1];
	if length_byte & 0x80 == 0 {
		// Short form: length is in the single byte
		Some((length_byte as usize, 2))
	} else {
		// Long form: length is encoded in the following bytes
		let length_bytes = (length_byte & 0x7F) as usize;
		if length_bytes == 0 || data.len() < 2 + length_bytes {
			return None;
		}

		// Compute the content length by folding over the length bytes
		let content_length = (0..length_bytes)
			.map(|i| data[2 + i] as usize)
			.fold(0usize, |acc, byte| (acc << 8) | byte);

		Some((content_length, 2 + length_bytes))
	}
}

/// Convert DER-encoded ECDSA signature to raw 64-byte format.
///
/// This function parses a DER-encoded ECDSA signature and converts it to the
/// raw 64-byte format (32 bytes r + 32 bytes s) commonly used in cryptographic
/// operations.
///
/// # Arguments
///
/// * `signature_bytes` - DER-encoded ECDSA signature bytes
///
/// # Returns
///
/// * `Ok([u8; 64])` - Raw signature in r||s format
/// * `Err(CertificateError)` - If parsing fails
///
/// # Example
///
/// ```rust
/// use x509::utils::der_to_raw_signature;
///
/// // Example DER-encoded signature with valid r and s values
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let der_sig = [
///     0x30, 0x44, // SEQUENCE, length 68
///     0x02, 0x20, // INTEGER, length 32 (r)
///     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
///     0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
///     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
///     0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
///     0x02, 0x20, // INTEGER, length 32 (s)
///     0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
///     0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
///     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
///     0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
/// ];
/// let raw_sig = der_to_raw_signature(&der_sig)?;
/// assert_eq!(raw_sig.len(), 64);
/// # Ok(())
/// # }
/// ```
pub fn der_to_raw_signature(signature_bytes: impl AsRef<[u8]>) -> Result<[u8; 64], CertificateError> {
	if let Ok((r_array, s_array)) = parse_der_ecdsa_signature(signature_bytes.as_ref()) {
		let mut sig_array = [0u8; 64];
		sig_array[..32].copy_from_slice(&r_array);
		sig_array[32..].copy_from_slice(&s_array);
		Ok(sig_array)
	} else {
		Err(CertificateError::InvalidCertificate)
	}
}

/// Generic ECDSA signature verification with multiple signature format support.
///
/// This internal helper function implements the common ECDSA verification logic
/// for both Secp256r1 and Secp256k1 curves, handling both DER-encoded and raw
/// signature formats.
///
/// # Type Parameters
///
/// * `K` - Public key type (Secp256r1PublicKey or Secp256k1PublicKey)
/// * `S` - Signature type (Secp256r1Signature or Secp256k1Signature)
///
/// # Arguments
///
/// * `public_key` - The public key for verification
/// * `signature_bytes` - Signature bytes (DER or raw format)
/// * `tbs_der` - To-be-signed certificate data
/// * `hash_algorithm` - Hash algorithm for fallback verification
/// * `sig_from_bytes` - Function to create signature from raw bytes
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded
/// * `Ok(false)` - Signature verification failed
/// * `Err(CertificateError)` - Error during verification process
fn try_verify_ecdsa_generic<K, S, F>(
	public_key: K,
	signature_bytes: impl AsRef<[u8]>,
	tbs_der: impl AsRef<[u8]>,
	hash_algorithm: HashAlgorithm,
	sig_from_bytes: F,
) -> Result<bool, CertificateError>
where
	K: CryptoVerifierWithOptions<S>,
	F: Fn(&[u8; 64]) -> Result<S, CertificateError>,
{
	let signature_bytes = signature_bytes.as_ref();
	let tbs_der = tbs_der.as_ref();

	// Try DER-encoded signature first
	if signature_bytes.len() >= 2 && signature_bytes[0] == 0x30 {
		if let Ok(sig_array) = der_to_raw_signature(signature_bytes) {
			let signature = sig_from_bytes(&sig_array)?;

			// For X.509 certificates, hash the TBS data with the specified algorithm
			// then verify using raw mode (matching TypeScript implementation)
			let hash_bytes = hash_algorithm.hash(tbs_der);
			let options = SigningOptions::raw(); // Use raw verification with pre-hashed data
			if public_key
				.verify_with_options(&hash_bytes, &signature, options)
				.is_ok()
			{
				return Ok(true);
			}
		}
	}
	// Try raw 64-byte signature
	else if signature_bytes.len() == 64 {
		let sig_array: [u8; 64] = signature_bytes
			.try_into()
			.map_err(|_| CertificateError::InvalidCertificate)?;
		let signature = sig_from_bytes(&sig_array)?;

		// For raw signatures, also use the raw hash approach
		let hash_bytes = hash_algorithm.hash(tbs_der);
		let options = SigningOptions::raw();
		if public_key
			.verify_with_options(&hash_bytes, &signature, options)
			.is_ok()
		{
			return Ok(true);
		}
	}

	Ok(false)
}

/// Verify ECDSA signature using Secp256r1 curve with multiple format support.
///
/// This function attempts to verify an ECDSA signature using the Secp256r1
/// elliptic curve. It supports both DER-encoded and raw 64-byte signature
/// formats, and tries multiple verification approaches including direct
/// verification and hash-based verification.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw bytes of the Secp256r1 public key
/// * `signature_bytes` - Signature bytes (DER or raw format)
/// * `tbs_der` - To-be-signed certificate data in DER format
/// * `hash_algorithm` - Hash algorithm to use for fallback verification
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded
/// * `Ok(false)` - Signature verification failed
/// * `Err(CertificateError)` - Error during verification process
///
/// # Example
///
/// ```rust,no_run
/// use x509::utils::try_verify_ecdsa_secp256r1;
/// use crypto::HashAlgorithm;
///
/// let public_key_bytes = &[/* 65 bytes of uncompressed public key */];
/// let signature_bytes = &[/* DER or raw signature bytes */];
/// let tbs_data = &[/* certificate data to verify */];
///
/// let result = try_verify_ecdsa_secp256r1(
///     public_key_bytes,
///     signature_bytes,
///     tbs_data,
///     HashAlgorithm::Sha2_256
/// );
/// ```
pub fn try_verify_ecdsa_secp256r1(
	public_key_bytes: impl AsRef<[u8]>,
	signature_bytes: impl AsRef<[u8]>,
	tbs_der: impl AsRef<[u8]>,
	hash_algorithm: HashAlgorithm,
) -> Result<bool, CertificateError> {
	let public_key =
		Secp256r1PublicKey::try_from(public_key_bytes.as_ref()).map_err(|_| CertificateError::InvalidCertificate)?;

	try_verify_ecdsa_generic(public_key, signature_bytes, tbs_der, hash_algorithm, |sig_array| {
		Secp256r1Signature::from_bytes((sig_array).into()).map_err(|_| CertificateError::InvalidCertificate)
	})
}

/// Verify ECDSA signature using Secp256k1 curve with multiple format support.
///
/// This function attempts to verify an ECDSA signature using the Secp256k1
/// elliptic curve. It supports both DER-encoded and raw  64-byte signature
/// formats, and tries multiple verification approaches including direct
/// verification and hash-based verification.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw bytes of the Secp256k1 public key
/// * `signature_bytes` - Signature bytes (DER or raw format)
/// * `tbs_der` - To-be-signed certificate data in DER format
/// * `hash_algorithm` - Hash algorithm to use for fallback verification
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded
/// * `Ok(false)` - Signature verification failed
/// * `Err(CertificateError)` - Error during verification process
///
/// # Example
///
/// ```rust,no_run
/// use x509::utils::try_verify_ecdsa_secp256k1;
/// use crypto::HashAlgorithm;
///
/// let public_key_bytes = &[/* 65 bytes of uncompressed public key */];
/// let signature_bytes = &[/* DER or raw signature bytes */];
/// let tbs_data = &[/* certificate data to verify */];
///
/// let result = try_verify_ecdsa_secp256k1(
///     public_key_bytes,
///     signature_bytes,
///     tbs_data,
///     HashAlgorithm::Sha2_256
/// );
/// ```
pub fn try_verify_ecdsa_secp256k1(
	public_key_bytes: impl AsRef<[u8]>,
	signature_bytes: impl AsRef<[u8]>,
	tbs_der: impl AsRef<[u8]>,
	hash_algorithm: HashAlgorithm,
) -> Result<bool, CertificateError> {
	let public_key =
		Secp256k1PublicKey::try_from(public_key_bytes.as_ref()).map_err(|_| CertificateError::InvalidCertificate)?;

	try_verify_ecdsa_generic(public_key, signature_bytes, tbs_der, hash_algorithm, |sig_array| {
		Secp256k1Signature::from_bytes((sig_array).into()).map_err(|_| CertificateError::InvalidCertificate)
	})
}

/// Verify Ed25519 signature for X.509 certificates.
///
/// This function verifies an Ed25519 signature against certificate data using
/// the raw signing mode as specified for X.509 certificate verification.
/// Ed25519 signatures are always 64 bytes and use a fixed format.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw bytes of the Ed25519 public key (32 bytes)
/// * `signature_bytes` - Ed25519 signature bytes (must be exactly 64 bytes)
/// * `tbs_der` - To-be-signed certificate data in DER format
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded
/// * `Ok(false)` - Signature verification failed
/// * `Err(CertificateError)` - Error during verification process
///
/// # Example
///
/// ```rust,no_run
/// use x509::utils::verify_ed25519_signature;
///
/// let public_key_bytes = &[/* 32 bytes of Ed25519 public key */];
/// let signature_bytes = &[/* 64 bytes of Ed25519 signature */];
/// let tbs_data = &[/* certificate data to verify */];
///
/// let result = verify_ed25519_signature(
///     public_key_bytes,
///     signature_bytes,
///     tbs_data
/// );
/// ```
pub fn verify_ed25519_signature(
	public_key_bytes: impl AsRef<[u8]>,
	signature_bytes: impl AsRef<[u8]>,
	tbs_der: impl AsRef<[u8]>,
) -> Result<bool, CertificateError> {
	let signature_bytes = signature_bytes.as_ref();
	if signature_bytes.len() != 64 {
		return Ok(false);
	}

	let public_key =
		Ed25519PublicKey::try_from(public_key_bytes.as_ref()).map_err(|_| CertificateError::InvalidCertificate)?;

	let sig_array: [u8; 64] = signature_bytes
		.try_into()
		.map_err(|_| CertificateError::InvalidCertificate)?;
	let signature = Ed25519Signature::from_bytes(&sig_array);

	let options = SigningOptions::raw();
	public_key
		.verify_with_options(tbs_der.as_ref(), &signature, options)
		.map(|()| true)
		.map_err(|_| CertificateError::CertificateSignatureVerificationFailed)
}

/// Verify ECDSA signature trying both Secp256r1 and Secp256k1 curves.
///
/// This function attempts to verify an ECDSA signature by trying both supported
/// elliptic curves (Secp256r1/P-256 and Secp256k1). This is useful when the
/// specific curve is not known from the algorithm identifier, as is the case
/// with the generic "ECDSA with SHA-256" algorithm identifier.
///
/// The function tries Secp256r1 first (as it's more common in X.509), then
/// falls back to Secp256k1 if verification fails.
///
/// # Arguments
///
/// * `public_key_bytes` - Raw bytes of the ECDSA public key
/// * `signature_bytes` - Signature bytes (DER or raw format)
/// * `tbs_der` - To-be-signed certificate data in DER format
/// * `hash_algorithm` - Hash algorithm to use for verification
///
/// # Returns
///
/// * `Ok(true)` - Signature verification succeeded with one of the curves
/// * `Ok(false)` - Signature verification failed with both curves
/// * `Err(CertificateError)` - Error during verification process
///
/// # Example
///
/// ```rust,no_run
/// use x509::utils::verify_ecdsa_signature;
/// use crypto::HashAlgorithm;
///
/// // This example shows the function signature but does not run
/// // because it would require valid cryptographic data
/// let public_key_bytes = &[/* ECDSA public key bytes */];
/// let signature_bytes = &[/* signature bytes */];
/// let tbs_data = &[/* certificate data to verify */];
///
/// let result = verify_ecdsa_signature(
///     public_key_bytes,
///     signature_bytes,
///     tbs_data,
///     HashAlgorithm::Sha2_256
/// );
/// ```
pub fn verify_ecdsa_signature(
	public_key_bytes: impl AsRef<[u8]>,
	signature_bytes: impl AsRef<[u8]>,
	tbs_der: impl AsRef<[u8]>,
	hash_algorithm: HashAlgorithm,
) -> Result<bool, CertificateError> {
	// Try Secp256r1 first (more common in X.509)
	if let Ok(result) = try_verify_ecdsa_secp256r1(&public_key_bytes, &signature_bytes, &tbs_der, hash_algorithm) {
		if result {
			return Ok(true);
		}
	}

	// Try Secp256k1 if Secp256r1 failed
	try_verify_ecdsa_secp256k1(public_key_bytes, signature_bytes, tbs_der, hash_algorithm)
}

#[cfg(test)]
mod tests {
	use asn1::oids;
	use asn1::BitString;

	use super::*;

	#[cfg(feature = "serde")]
	use crate::DistinguishedName;

	#[test]
	fn test_create_dn() {
		// Test cases: (input_pairs, expected_length, should_succeed)
		let test_cases = [
			// Valid cases
			(&[][..], 0, true),                                 // Empty pairs
			(&[(oids::CN, "single.example.com")][..], 1, true), // Single attribute
			(
				&[
					(oids::CN, "example.com"),
					(oids::O, "Example Organization"),
					(oids::OU, "IT Department"),
					(oids::C, "US"),
				][..],
				4,
				true,
			), // Multiple attributes
			(&[(oids::CN, "test with spaces"), (oids::O, "Org,with=special;chars")][..], 2, true), // Special characters
			// Invalid case
			(&[("invalid.oid", "value")][..], 0, false), // Invalid OID
		];

		for (pairs, expected_len, should_succeed) in test_cases {
			let result = create_dn(pairs);

			if should_succeed {
				let dn = result.unwrap();
				assert_eq!(dn.len(), expected_len, "Failed for pairs: {pairs:?}");

				// Verify each attribute is correctly stored
				for (i, (expected_oid, expected_value)) in pairs.iter().enumerate() {
					assert_eq!(dn[i].len(), 1);
					assert_eq!(dn[i].get(0).unwrap().attribute_type.to_string(), *expected_oid);

					let ia5_string: Ia5String = dn[i].get(0).unwrap().attribute_value.decode_as().unwrap();
					assert_eq!(ia5_string.as_str(), *expected_value);
				}
			} else {
				assert!(result.is_err(), "Expected error for pairs: {pairs:?}");
			}
		}
	}

	#[test]
	fn test_dn_to_string() {
		// Test cases: (input_pairs, expected_contains, should_not_contain)
		let test_cases = [
			// Empty DN
			(&[][..], vec![], vec![", "]),
			// Single attribute
			(&[(oids::CN, "single.example.com")][..], vec!["2.5.4.3=single.example.com"], vec![", "]),
			// Multiple attributes
			(
				&[
					(oids::CN, "example.com"),
					(oids::O, "Example Organization"),
					(oids::OU, "IT Department"),
					(oids::C, "US"),
				][..],
				vec!["example.com", "Example Organization", "IT Department", "US", "2.5.4.3=", "2.5.4.10=", ", "],
				vec![],
			),
			// Special characters
			(
				&[(oids::CN, "test with spaces"), (oids::O, "Org,with=special;chars")][..],
				vec!["test with spaces", "Org,with=special;chars", ", "],
				vec![],
			),
		];

		for (pairs, should_contain, should_not_contain) in test_cases {
			let dn = if pairs.is_empty() {
				Vec::new()
			} else {
				create_dn(pairs).unwrap()
			};

			let dn_string = dn_to_string(&dn);

			for expected in should_contain {
				assert!(dn_string.contains(expected), "DN string '{dn_string}' should contain '{expected}'");
			}

			for unexpected in should_not_contain {
				assert!(!dn_string.contains(unexpected), "DN string '{dn_string}' should not contain '{unexpected}'");
			}
		}
	}

	#[test]
	fn test_generate_key_identifier() {
		// Test cases: (input_bytes, description)
		let test_cases = [
			(&[0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..], "basic public key"),
			(&[0x04, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18][..], "different public key"),
			(&[][..], "empty public key"),
			(&[0x30, 0x59, 0x30, 0x13][..], "realistic key prefix"),
		];

		let mut previous_hashes = Vec::new();

		for (key_bytes, description) in test_cases {
			let bit_string = BitString::new(0, key_bytes).unwrap();
			let key_id = generate_key_identifier(&bit_string).unwrap();

			// SHA-1 always produces 20 bytes
			assert_eq!(key_id.len(), 20, "Hash length should be 20 for {description}");

			// Different inputs should produce different outputs (except for identical inputs)
			for (i, prev_hash) in previous_hashes.iter().enumerate() {
				if key_bytes != test_cases[i].0 {
					assert_ne!(
						&key_id, prev_hash,
						"Different inputs should produce different hashes: {} vs {}",
						description, test_cases[i].1
					);
				}
			}

			previous_hashes.push(key_id);
		}
	}

	#[test]
	fn test_parse_key_identifier() {
		// Test cases: (input_data, expected_result)
		let test_cases = [
			// Valid cases
			(
				&[
					0x04, 0x14, // OCTET STRING, length 20
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14,
				][..],
				Some(vec![
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14,
				]),
			),
			(&[0x04, 0x04, 0xAA, 0xBB, 0xCC, 0xDD][..], Some(vec![0xAA, 0xBB, 0xCC, 0xDD])),
			(&[0x04, 0x00][..], Some(vec![])), // Empty key identifier
			// Invalid cases
			(&[0x05, 0x04, 0x01, 0x02, 0x03, 0x04][..], None), // Wrong tag (not OCTET STRING)
			(&[0x04][..], None),                               // Too short (missing length)
			(&[0x04, 0x10, 0x01, 0x02][..], None),             // Length longer than remaining bytes
			(&[][..], None),                                   // Empty input
		];

		for (input, expected) in test_cases {
			assert_eq!(parse_key_identifier(input), expected, "Failed for input: {input:02x?}");
		}
	}

	#[test]
	fn test_parse_authority_key_identifier() {
		// Test cases: (input_data, expected_result)
		let test_cases = [
			// Valid cases
			(
				&[
					0x30, 0x16, // SEQUENCE, length 22
					0x80, 0x14, // [0] IMPLICIT, length 20
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14,
				][..],
				Some(vec![
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
					0x11, 0x12, 0x13, 0x14,
				]),
			),
			(
				&[
					0x30, 0x06, // SEQUENCE, length 6
					0x80, 0x04, // [0] IMPLICIT, length 4
					0xAA, 0xBB, 0xCC, 0xDD,
				][..],
				Some(vec![0xAA, 0xBB, 0xCC, 0xDD]),
			),
			(
				&[
					0x30, 0x02, // SEQUENCE, length 2
					0x80, 0x00, // [0] IMPLICIT, length 0
				][..],
				Some(vec![]), // Empty key identifier
			),
			// Invalid cases
			(&[0x04, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04][..], None), // Wrong tag (not SEQUENCE)
			(&[0x30, 0x02, 0x81, 0x00][..], None),                         // No [0] tag inside SEQUENCE ([1] instead)
			(&[0x30, 0x16, 0x80][..], None),                               // Too short for SEQUENCE
			(&[0x30, 0x06, 0x80, 0x10, 0x01, 0x02][..], None),             // Length mismatch
			(&[][..], None),                                               // Empty input
			(&[0x30, 0x01, 0x80][..], None),                               // SEQUENCE too short for proper parsing
		];

		for (input, expected) in test_cases {
			assert_eq!(parse_authority_key_identifier(input), expected, "Failed for input: {input:02x?}");
		}
	}

	#[test]
	fn test_parse_der_length() {
		// Test cases: (input_data, expected_result)
		let test_cases = [
			// Short form cases
			(&[0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05][..], Some((5, 2))),
			(&[0x30, 0x7F][..], Some((127, 2))), // Maximum short form
			(&[0x30, 0x00][..], Some((0, 2))),   // Zero length
			// Long form cases
			(&[0x30, 0x81, 0x80][..], Some((128, 3))),               // 1 byte length
			(&[0x30, 0x82, 0x01, 0x00][..], Some((256, 4))),         // 2 byte length
			(&[0x30, 0x83, 0x01, 0x00, 0x00][..], Some((65536, 5))), // 3 byte length
			// Real certificate data example
			(&[0x30, 0x82, 0x03, 0x8a, 0x30, 0x82, 0x02, 0x72][..], Some((906, 4))),
			// Invalid cases
			(&[][..], None),                 // Empty data
			(&[0x31, 0x05][..], None),       // Wrong tag
			(&[0x30][..], None),             // Missing length byte
			(&[0x30, 0x82][..], None),       // Long form missing bytes
			(&[0x30, 0x82, 0x01][..], None), // Long form incomplete
			(&[0x30, 0x80][..], None),       // Invalid long form (length=0)
		];

		for (input, expected) in test_cases {
			assert_eq!(parse_der_length(input), expected, "Failed for input: {input:02x?}");
		}
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
		let ia5_string: Ia5String = single_dn[0]
			.get(0)
			.unwrap()
			.attribute_value
			.decode_as()
			.unwrap();
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
			let ia5_string: Ia5String = multi_dn[i]
				.get(0)
				.unwrap()
				.attribute_value
				.decode_as()
				.unwrap();
			assert_eq!(ia5_string.as_str(), *expected_value);
		}

		// Test with direct OID
		let oid_pairs = vec![NameValuePair { name: oids::CN.to_string(), value: "direct_oid.com".to_string() }];
		let oid_dn = name_value_pairs_to_dn(&oid_pairs).unwrap();
		assert_eq!(oid_dn.len(), 1);
		assert_eq!(oid_dn[0].get(0).unwrap().attribute_type.to_string(), oids::CN);
		let ia5_string: Ia5String = oid_dn[0]
			.get(0)
			.unwrap()
			.attribute_value
			.decode_as()
			.unwrap();
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
	fn test_der_to_raw_signature() {
		// Test cases for DER to raw signature conversion
		// These test vectors represent valid DER SEQUENCE structures for ECDSA signatures

		// Test with valid DER signature (minimal valid structure)
		// This represents: SEQUENCE { INTEGER r (32 bytes), INTEGER s (32 bytes) }
		let valid_der = vec![
			0x30, 0x44, // SEQUENCE, length 68
			0x02, 0x20, // INTEGER, length 32 (r value)
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x02,
			0x20, // INTEGER, length 32 (s value)
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
			0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		];

		let result = der_to_raw_signature(&valid_der).unwrap();
		assert_eq!(result.len(), 64);

		// Verify r and s values are correctly extracted
		let expected_r = [
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		];
		let expected_s = [
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
			0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		];

		assert_eq!(&result[..32], &expected_r);
		assert_eq!(&result[32..], &expected_s);

		// Test with invalid DER signatures
		assert!(der_to_raw_signature([]).is_err()); // Empty
		assert!(der_to_raw_signature([0x31, 0x44]).is_err()); // Wrong tag
		assert!(der_to_raw_signature([0x30, 0x02]).is_err()); // Too short
	}

	#[test]
	fn test_verify_ed25519_signature() {
		let tbs_der = b"test data to sign";
		let test_cases = [
			// Invalid signature lengths (should return Ok(false))
			(32, 32, Ok(false)),
			(32, 96, Ok(false)),
			(32, 0, Ok(false)),
			(32, 128, Ok(false)),
			// Invalid public key lengths (should return Err)
			(16, 64, Err(())),
			(0, 64, Err(())),
			(64, 64, Err(())),
			// Valid lengths but invalid key data (should return Err)
			(32, 64, Err(())),
		];

		for (pub_key_len, sig_len, expected) in test_cases {
			let public_key_bytes = vec![0u8; pub_key_len];
			let signature_bytes = vec![0u8; sig_len];

			let result = verify_ed25519_signature(&public_key_bytes, &signature_bytes, tbs_der);
			match expected {
				Ok(expected_bool) => {
					assert_eq!(result.unwrap(), expected_bool);
				}
				Err(_) => {
					assert!(result.is_err());
				}
			}
		}
	}

	#[test]
	fn test_ecdsa_signature_verification_error_cases() {
		let tbs_der = b"test data to sign";

		// Test cases: (pub_key_len, signature_data, description, should_error)
		let test_cases = [
			// Invalid signature lengths for raw format
			(65, vec![0u8; 32], true),
			(65, vec![0u8; 96], true),
			(65, vec![], true),
			// Invalid public key lengths
			(16, vec![0u8; 64], true),
			(0, vec![0u8; 64], true),
			(32, vec![0u8; 64], true),
			// Invalid DER signature format
			(65, vec![0x30, 0x02, 0x01], true),
			(65, vec![0x30], true),
			// Valid lengths but dummy data (should error due to invalid key)
			(65, vec![0u8; 64], true),
		];

		// Macro to test both curves with the same logic
		macro_rules! test_curve {
			($curve_fn:ident) => {
				for (pub_key_len, signature_bytes, should_error) in &test_cases {
					let public_key_bytes = vec![0u8; *pub_key_len];
					let result = $curve_fn(&public_key_bytes, signature_bytes, tbs_der, HashAlgorithm::Sha2_256);

					if *should_error {
						assert!(result.is_err() || result.unwrap() == false);
					} else {
						assert!(result.is_ok());
					}
				}
			};
		}

		// Test both curves
		test_curve!(try_verify_ecdsa_secp256r1);
		test_curve!(try_verify_ecdsa_secp256k1);
	}

	#[test]
	fn test_verify_ecdsa_signature_fallback() {
		let public_key_bytes = vec![0u8; 65]; // Invalid but correct length
		let signature_bytes = vec![0u8; 64];
		let tbs_der = b"test data to sign";

		let result = verify_ecdsa_signature(&public_key_bytes, &signature_bytes, tbs_der, HashAlgorithm::Sha2_256);
		assert!(result.is_err());

		let public_key_bytes = vec![0u8; 16];
		let result = verify_ecdsa_signature(&public_key_bytes, &signature_bytes, tbs_der, HashAlgorithm::Sha2_256);
		assert!(result.is_err());
	}

	#[test]
	fn test_signature_format_detection() {
		let public_key_bytes = vec![0u8; 65];
		let tbs_der = b"test data";
		let test_cases = [
			// DER format detection (starts with 0x30)
			(vec![0x30, 0x44, 0x02, 0x20], true),
			// Raw format (64 bytes, not starting with 0x30)
			(vec![0x01; 64], true),
			// Raw format with different starting byte
			(vec![0xFF; 64], true),
			// Invalid length (not 64 and not DER)
			(vec![0x01; 48], true),
			(vec![0x01; 32], true),
			// Empty signature
			(vec![], true),
			// Single byte
			(vec![0x30], true),
		];

		for (signature_bytes, should_error) in test_cases {
			let result =
				try_verify_ecdsa_secp256r1(&public_key_bytes, &signature_bytes, tbs_der, HashAlgorithm::Sha2_256);
			if should_error {
				assert!(result.is_err());
			} else {
				assert!(result.is_ok());
			}
		}
	}

	#[test]
	fn test_hash_algorithm_support() {
		let public_key_bytes = vec![0u8; 65];
		let signature_bytes = vec![0u8; 64];
		let tbs_der = b"test data";

		let hash_algorithms = [HashAlgorithm::Sha2_256, HashAlgorithm::Sha3_256];
		for hash_algo in hash_algorithms {
			let result = try_verify_ecdsa_secp256r1(&public_key_bytes, &signature_bytes, tbs_der, hash_algo);
			assert!(result.is_err());

			let result = try_verify_ecdsa_secp256k1(&public_key_bytes, &signature_bytes, tbs_der, hash_algo);
			assert!(result.is_err());
		}
	}
}
