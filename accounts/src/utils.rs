use std::str::FromStr as _;

use rand_core::TryRngCore as _;
use secrecy::SecretBox;

use crate::error::AccountError;
use crate::{Index, Seed};

/// Derives a 32-byte seed from a passphrase.
/// Returns an error if the passphrase is too short after normalization.
pub(crate) fn seed_from_passphrase(passphrase: &str) -> Result<Seed, AccountError> {
	let min_passphrase_length = 60;
	let clean_passphrase = passphrase.to_lowercase().replace(" ", "");

	let clean_passphrase_buffer = clean_passphrase.as_bytes();
	if clean_passphrase_buffer.len() < min_passphrase_length {
		return Err(AccountError::PassphraseWeak);
	}

	let mut key = [0u8; 32];
	pbkdf2::pbkdf2_hmac::<sha2::Sha256>(clean_passphrase_buffer, clean_passphrase_buffer, 64000, &mut key);

	Ok(key)
}

/// Combines a 32-byte seed and a 4-byte index into a 36-byte array.
/// The index is encoded in big-endian order at the end of the array.
pub(crate) fn combine_seed_and_index(seed: &Seed, index: Index) -> [u8; 36] {
	let mut indexed_seed = [0u8; 36];
	indexed_seed[..32].copy_from_slice(seed);
	indexed_seed[32] = (index >> 24) as u8;
	indexed_seed[33] = (index >> 16) as u8;
	indexed_seed[34] = (index >> 8) as u8;
	indexed_seed[35] = index as u8;

	indexed_seed
}

/// Generates a random 24-word passphrase using the bip39 English word list.
/// Returns an error if the OS RNG fails.
pub(crate) fn generate_random_passphrase() -> Result<SecretBox<Vec<String>>, AccountError> {
	let words = bip39_dict::ENGLISH.words;
	let word_count = words.len() as u32;
	let passphrase: Result<Vec<String>, AccountError> = (0..24)
		.map(|_| {
			let idx = rand_core::OsRng.try_next_u32().map_err(|_| AccountError::InvalidConstruction)?;
			let word = words[(idx % word_count) as usize];

			String::from_str(word).map_err(|_| AccountError::InvalidConstruction)
		})
		.collect();

	Ok(SecretBox::new(Box::new(passphrase?)))
}

/// Generates a random 32-byte seed using the OS RNG.
/// Returns an error if the OS RNG fails.
pub(crate) fn generate_random_seed() -> Result<SecretBox<Seed>, AccountError> {
	let mut seed_buffer = [0u8; 32];

	let check = rand_core::OsRng.try_fill_bytes(&mut seed_buffer);
	if check.is_err() {
		return Err(AccountError::InvalidConstruction);
	}

	Ok(SecretBox::new(Box::new(seed_buffer)))
}

#[cfg(test)]
mod tests {
	use secrecy::ExposeSecret;

	use super::*;

	#[test]
	fn test_seed_from_passphrase() {
		let passphrase = "panic category office glow ski camera file slight room escape indicate fiction";
		let seed = seed_from_passphrase(passphrase);

		assert!(seed.is_ok());
		assert_eq!(seed.unwrap().len(), 32);
	}

	#[test]
	fn test_combine_seed_and_index() {
		let seed = [1u8; 32];
		let index = 0x12345678;
		let combined = combine_seed_and_index(&seed, index);

		assert_eq!(&combined[..32], &seed);
		assert_eq!(combined[32], 0x12);
		assert_eq!(combined[33], 0x34);
		assert_eq!(combined[34], 0x56);
		assert_eq!(combined[35], 0x78);
	}

	#[test]
	fn test_generate_random_passphrase() {
		let passphrase = generate_random_passphrase().unwrap();
		let passphrase = passphrase.expose_secret();

		assert_eq!(passphrase.len(), 24);

		for word in passphrase {
			assert!(!word.is_empty());
		}
	}

	#[test]
	fn test_generate_random_seed() {
		let seed = generate_random_seed().unwrap();
		let seed = seed.expose_secret();

		assert_eq!(seed.len(), 32);
	}
}
