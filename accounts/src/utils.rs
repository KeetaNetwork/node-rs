use crypto::prelude::*;
use secrecy::ExposeSecret;

use crate::error::AccountError;
use crate::{Index, Seed};

/// Hash function using the crypto crate's default hash algorithm (SHA3-256)
pub(crate) fn hash_message(data: &[u8]) -> Vec<u8> {
	hash_default(data).to_vec()
}

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

/// Format a public key with checksum and base32 encoding
pub(crate) fn format_public_key(public_key_bytes: &[u8], algorithm: Algorithm) -> Result<String, AccountError> {
	// Start with algorithm identifier
	let mut pub_key_values = vec![algorithm.id()];

	// Add the public key bytes
	pub_key_values.extend_from_slice(public_key_bytes);

	// Calculate checksum using crypto crate hash abstraction
	let checksum_of = Vec::from(&pub_key_values[..]);
	let checksum: [u8; 32] = hash_array(&checksum_of, None).map_err(AccountError::from)?;

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
		return Err(AccountError::InvalidPrefix);
	}

	// Encode as base32
	let pub_key_formatted = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &pub_key_values);

	Ok(format!("keeta_{pub_key_formatted}"))
}

/// Parse a formatted public key string
pub(crate) fn parse_public_key(formatted_key: &str) -> Result<(Vec<u8>, Algorithm), AccountError> {
	// Remove "keeta_" prefix
	let encoded = formatted_key.strip_prefix("keeta_").ok_or(AccountError::InvalidPrefix)?;

	// Decode base32
	let decoded = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, encoded)
		.ok_or(AccountError::InvalidPrefix)?;
	if decoded.len() < 6 {
		// At least 1 byte algorithm + 1 byte pubkey + 5 bytes checksum
		return Err(AccountError::InvalidPrefix);
	}

	// Extract algorithm
	let algorithm = Algorithm::from_id(decoded[0]).map_err(AccountError::from)?;

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

#[cfg(test)]
mod tests {
	use secrecy::{ExposeSecret, SecretBox};

	use super::*;

	#[test]
	fn test_hash_message() {
		let test_data = b"hello world";
		let hash1 = hash_message(test_data);
		let hash2 = hash_message(test_data);

		// Hash should be deterministic
		assert_eq!(hash1, hash2);
		// Hash should be 32 bytes (SHA3-256)
		assert_eq!(hash1.len(), 32);
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
