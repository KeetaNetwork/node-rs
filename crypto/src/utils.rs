use sha3::Digest;

use crate::{algorithms::Algorithm, error::CryptoError};

/// Format a public key with checksum and base32 encoding
pub fn format_public_key(public_key_bytes: &[u8], algorithm: Algorithm) -> Result<String, CryptoError> {
	// Start with algorithm identifier
	let mut pub_key_values = vec![algorithm.id()];

	// Add the public key bytes
	pub_key_values.extend_from_slice(public_key_bytes);

	// Calculate checksum
	let checksum_of = Vec::from(&pub_key_values[..]);
	let mut hasher = sha3::Sha3_256::new();
	hasher.update(&checksum_of);
	let checksum = hasher.finalize();

	// Add first 5 bytes of checksum
	pub_key_values.extend_from_slice(&checksum[..5]);

	// Expected lengths:
	// secp256k1: 1 (algo) + 33 (compressed pubkey) + 5 (checksum) = 39 bytes
	// ed25519: 1 (algo) + 32 (pubkey) + 5 (checksum) = 38 bytes
	let expected_lengths = match algorithm {
		Algorithm::Secp256k1 => vec![39],
		Algorithm::Ed25519 => vec![38],
		Algorithm::Secp256r1 => vec![39], // Same as secp256k1
	};

	if !expected_lengths.contains(&pub_key_values.len()) {
		return Err(CryptoError::InvalidPublicKey);
	}

	// Encode as base32
	let pub_key_formatted = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &pub_key_values);

	Ok(format!("keeta_{pub_key_formatted}"))
}

/// Parse a formatted public key string
pub fn parse_public_key(formatted_key: &str) -> Result<(Vec<u8>, Algorithm), CryptoError> {
	// Remove "keeta_" prefix
	let encoded = formatted_key.strip_prefix("keeta_").ok_or(CryptoError::InvalidPublicKey)?;

	// Decode base32
	let decoded = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, encoded)
		.ok_or(CryptoError::InvalidPublicKey)?;

	if decoded.len() < 6 {
		// At least 1 byte algorithm + 1 byte pubkey + 5 bytes checksum
		return Err(CryptoError::InvalidPublicKey);
	}

	// Extract algorithm
	let algorithm = Algorithm::from_id(decoded[0])?;

	// Extract public key bytes (everything except first byte and last 5 bytes)
	let pubkey_end = decoded.len() - 5;
	let public_key_bytes = decoded[1..pubkey_end].to_vec();

	// Verify checksum
	let checksum_input = decoded[..pubkey_end].to_vec();
	let mut hasher = sha3::Sha3_256::new();
	hasher.update(&checksum_input);
	let calculated_checksum = hasher.finalize();

	let provided_checksum = &decoded[pubkey_end..];
	if provided_checksum != &calculated_checksum[..5] {
		return Err(CryptoError::InvalidPublicKey);
	}

	Ok((public_key_bytes, algorithm))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_format_and_parse_secp256k1() {
		// 33-byte compressed secp256k1 public key
		let pubkey = vec![0x02; 33];
		let formatted = format_public_key(&pubkey, Algorithm::Secp256k1).unwrap();

		assert!(formatted.starts_with("keeta_"));

		let (parsed_pubkey, algorithm) = parse_public_key(&formatted).unwrap();
		assert_eq!(pubkey, parsed_pubkey);
		assert_eq!(algorithm, Algorithm::Secp256k1);
	}

	#[test]
	fn test_format_and_parse_ed25519() {
		// 32-byte ed25519 public key
		let pubkey = vec![0x03; 32];
		let formatted = format_public_key(&pubkey, Algorithm::Ed25519).unwrap();

		assert!(formatted.starts_with("keeta_"));

		let (parsed_pubkey, algorithm) = parse_public_key(&formatted).unwrap();
		assert_eq!(pubkey, parsed_pubkey);
		assert_eq!(algorithm, Algorithm::Ed25519);
	}

	#[test]
	fn test_invalid_format() {
		// Wrong prefix
		assert!(parse_public_key("wrong_prefix").is_err());

		// Invalid base32
		assert!(parse_public_key("keeta_invalid@base32!").is_err());

		// Too short
		assert!(parse_public_key("keeta_aa").is_err());
	}

	#[test]
	fn test_checksum_validation() {
		let pubkey = vec![0x04; 33];
		let mut formatted = format_public_key(&pubkey, Algorithm::Secp256k1).unwrap();

		// Corrupt the last character (checksum)
		formatted.pop();
		formatted.push('x');

		assert!(parse_public_key(&formatted).is_err());
	}
}
