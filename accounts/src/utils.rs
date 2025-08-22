use crypto::prelude::*;
use secrecy::ExposeSecret;

use crate::error::AccountError;
use crate::{Index, Seed};

/// Combines a 32-byte seed and a 4-byte index into a 36-byte array.
pub(crate) fn combine_seed_and_index(seed: &Seed, index: Index) -> [u8; 36] {
	let mut indexed_seed = [0u8; 36];

	indexed_seed[..32].copy_from_slice(seed.expose_secret());
	indexed_seed[32] = (index >> 24) as u8;
	indexed_seed[33] = (index >> 16) as u8;
	indexed_seed[34] = (index >> 8) as u8;
	indexed_seed[35] = index as u8;

	indexed_seed
}

/// Format a key with checksum and base32 encoding (works for both cryptographic and identifier keys)
pub(crate) fn format_public_key_string(key_data: impl AsRef<[u8]>, key_type: u8) -> Result<String, AccountError> {
	let key_data = key_data.as_ref();

	// For identifier keys (2, 3, 4, 7), ensure exactly 32 bytes by hashing if needed
	let normalized_key_data = match key_type {
		2 | 3 | 4 | 7 => {
			// Identifier key types - need exactly 32 bytes
			if key_data.len() == 32 {
				key_data.to_vec()
			} else {
				// Hash the input to get exactly 32 bytes
				let hash_result: [u8; 32] = crypto::hash_array(key_data, None)?;
				hash_result.to_vec()
			}
		}
		_ => {
			// Cryptographic key types - use as-is
			key_data.to_vec()
		}
	};

	// Start with key type identifier
	let mut pub_key_values = vec![key_type];
	// Add the key bytes
	pub_key_values.extend_from_slice(&normalized_key_data);

	// Calculate checksum
	let calculated_checksum: [u8; 32] = crypto::hash_array(&pub_key_values, None)?;
	// Add first 5 bytes of checksum
	pub_key_values.extend_from_slice(&calculated_checksum[..5]);

	// Encode as base32
	let pub_key_formatted = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &pub_key_values);
	Ok(format!("keeta_{pub_key_formatted}"))
}

/// Parse a formatted public key string or hex format
/// Returns the public key bytes and optionally the algorithm (None for identifier keys)
pub(crate) fn parse_public_key(formatted_key: &str) -> Result<(Vec<u8>, Option<Algorithm>), AccountError> {
	// Check if it's hex format (0x[type][pubkey])
	if formatted_key.starts_with("0x") {
		let (bytes, algorithm) = parse_public_key_hex(formatted_key)?;
		return Ok((bytes, Some(algorithm)));
	}

	// Remove "keeta_" prefix for base32 format
	let encoded = formatted_key
		.strip_prefix("keeta_")
		.ok_or(AccountError::InvalidPrefix)?;

	// Decode base32
	let decoded = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, encoded)
		.ok_or(AccountError::InvalidPrefix)?;
	if decoded.len() < 6 {
		// At least 1 byte type + 1 byte key + 5 bytes checksum
		return Err(AccountError::InvalidPrefix);
	}

	// Extract key type (could be algorithm or identifier type)
	let key_type = decoded[0];

	// Try to parse as algorithm first, then check if it's a valid identifier type
	let algorithm = match Algorithm::from_id(key_type) {
		Ok(alg) => Some(alg),
		Err(_) => {
			// Check if it's a valid identifier key type
			match key_type {
				2 | 3 | 4 | 7 => None, // NETWORK, TOKEN, STORAGE, MULTISIG
				_ => return Err(AccountError::InvalidKeyType),
			}
		}
	};

	// Extract public key bytes (everything except first byte and last 5 bytes)
	let pubkey_end = decoded.len() - 5;
	let public_key_bytes = decoded[1..pubkey_end].to_vec();

	// Verify checksum
	let checksum_input = decoded[..pubkey_end].to_vec();
	let calculated_checksum: [u8; 32] = hash_array(&checksum_input, None).map_err(AccountError::from)?;

	let provided_checksum = &decoded[pubkey_end..];
	if provided_checksum != &calculated_checksum[..5] {
		return Err(AccountError::InvalidPrefix);
	}

	Ok((public_key_bytes, algorithm))
}

/// Create an identifier key from seed and index
pub(crate) fn create_identifier_key(seed: &Seed, index: Index) -> Result<(String, String), AccountError> {
	let seed_buffer = combine_seed_and_index(seed, index);
	let hash_result: [u8; 32] = crypto::hash_array(seed_buffer, None)?;

	// Use the full 32-byte hash as the identifier (as hex for internal use)
	let identifier = hex::encode(hash_result);

	// For the public key string, we'll use the full hash data
	// The actual "keeta_" formatting will be done by each key type
	let public_key = identifier.clone();
	Ok((identifier, public_key))
}

/// Helper function to parse hex format public key (`0x[type][pubkey]`)
fn parse_public_key_hex(hex_key: &str) -> Result<(Vec<u8>, Algorithm), AccountError> {
	// Remove "0x" prefix
	let hex_data = hex_key
		.strip_prefix("0x")
		.ok_or(AccountError::InvalidPrefix)?;

	// Decode hex
	let decoded = hex::decode(hex_data).map_err(|_| AccountError::InvalidPrefix)?;

	if decoded.is_empty() {
		return Err(AccountError::InvalidPrefix);
	}

	// First byte is the algorithm type
	let algorithm = Algorithm::from_id(decoded[0]).map_err(AccountError::from)?;

	// Rest is the public key
	let public_key_bytes = decoded[1..].to_vec();

	// Validate public key length based on algorithm
	let expected_lengths = match algorithm {
		Algorithm::Secp256k1 | Algorithm::Secp256r1 => &[33, 65][..], // compressed or uncompressed
		Algorithm::Ed25519 => &[32][..],                              // Ed25519 public keys are always 32 bytes
	};

	if !expected_lengths.contains(&public_key_bytes.len()) {
		return Err(AccountError::InvalidConstruction);
	}

	Ok((public_key_bytes, algorithm))
}

#[cfg(test)]
mod tests {
	use secrecy::{ExposeSecret, SecretBox};

	use super::*;
	use crypto::utils::{generate_random_passphrase, generate_random_seed, seed_from_passphrase};

	#[test]
	fn test_format_public_key_string() {
		let test_cases = [
			// Cryptographic key types
			(Algorithm::Secp256k1.id(), vec![0x02; 33]),
			(Algorithm::Ed25519.id(), vec![0x03; 32]),
			(Algorithm::Secp256r1.id(), vec![0x04; 33]),
			// Identifier key types
			(2, b"test-network-id".to_vec()),
			(3, b"test-token-id".to_vec()),
			(4, b"test-storage-id".to_vec()),
			(7, b"test-multisig-id".to_vec()),
		];

		for (key_type, test_data) in test_cases {
			let result = format_public_key_string(&test_data, key_type).unwrap();
			assert!(result.starts_with("keeta_"));

			// Verify we can parse it back
			let (parsed_bytes, parsed_algorithm) = parse_public_key(&result).unwrap();
			// For identifier keys, the parsed bytes should be the normalized 32-byte version
			if matches!(key_type, 2 | 3 | 4 | 7) {
				assert_eq!(parsed_bytes.len(), 32, "Identifier keys should normalize to 32 bytes");
				assert!(parsed_algorithm.is_none(), "Identifier keys should not have an algorithm");
			} else {
				assert_eq!(parsed_bytes, test_data, "Cryptographic key bytes should match");
				assert!(parsed_algorithm.is_some(), "Cryptographic keys should have an algorithm");
			}
		}
	}

	#[test]
	fn test_combine_seed_and_index() {
		let seed_data = [1u8; 32];
		let seed = SecretBox::new(Box::new(seed_data));
		let index = 0x12345678;

		let combined = combine_seed_and_index(&seed, index);
		assert_eq!(&combined[..32], &seed_data);
		assert_eq!(combined[32], 0x12);
		assert_eq!(combined[33], 0x34);
		assert_eq!(combined[34], 0x56);
		assert_eq!(combined[35], 0x78);
	}

	#[test]
	fn test_create_identifier_key() {
		let seed_data = [1u8; 32];
		let seed = SecretBox::new(Box::new(seed_data));
		let index = 42;

		let result = create_identifier_key(&seed, index).unwrap();
		let (identifier, public_key) = result;
		assert_eq!(identifier.len(), 64); // 32 bytes as hex = 64 chars
		assert_eq!(public_key, identifier); // No prefix, raw identifier like TypeScript
	}

	#[test]
	fn test_generate_random_passphrase() {
		let passphrase = generate_random_passphrase(None).unwrap();
		let passphrase = passphrase.expose_secret();
		assert_eq!(passphrase.len(), 24);

		// All words should be from the bip39 dictionary
		for word in passphrase {
			assert!(bip39_dict::ENGLISH.words.contains(&word.as_str()));
		}
	}

	#[test]
	fn test_generate_random_seed() {
		let seed = generate_random_seed().unwrap();
		let seed = seed.expose_secret();
		assert_eq!(seed.len(), 32);
		// Should not be all zeros (extremely unlikely)
		assert_ne!(*seed, [0u8; 32]);
	}

	#[test]
	fn test_seed_from_passphrase() {
		let passphrase = "panic category office glow ski camera file slight room escape indicate fiction";

		let seed = seed_from_passphrase(passphrase);
		assert!(seed.is_ok());

		let seed = seed.unwrap();
		assert_eq!(seed.expose_secret().len(), 32);
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
		let mut formatted = format_public_key_string(&pubkey, Algorithm::Secp256k1.id()).unwrap();

		// Corrupt the last character (checksum)
		formatted.pop();
		formatted.push('x');

		assert!(parse_public_key(&formatted).is_err());
	}

	#[test]
	fn test_hex_format_parsing() {
		let test_cases = [
			(Algorithm::Secp256k1, vec![0x02; 33]),
			(Algorithm::Ed25519, vec![0x03; 32]),
			(Algorithm::Secp256r1, vec![0x04; 33]),
		];

		for (algorithm, pubkey) in test_cases {
			// Test that base32 format works
			let base32_formatted = format_public_key_string(&pubkey, algorithm.id()).unwrap();
			let (parsed_pubkey, parsed_algorithm) = parse_public_key(&base32_formatted).unwrap();
			assert_eq!(pubkey, parsed_pubkey);
			assert_eq!(Some(algorithm), parsed_algorithm);
		}
	}

	#[test]
	fn test_invalid_hex_format() {
		// Missing 0x prefix
		assert!(parse_public_key("00123456").is_err());

		// Invalid hex characters
		assert!(parse_public_key("0xZZZZ").is_err());

		// Empty after 0x
		assert!(parse_public_key("0x").is_err());

		// Invalid algorithm ID
		assert!(parse_public_key("0xFF123456789012345678901234567890123456789012345678901234567890123456").is_err());

		// Wrong length for Ed25519 (should be 32 bytes)
		assert!(parse_public_key("0x01123456").is_err());
	}
}
