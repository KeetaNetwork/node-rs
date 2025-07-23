use core::str::FromStr;

use bip39_dict::DefaultDictionary;
use pbkdf2;
use rand_core::TryRngCore;
use secrecy::SecretBox;
use sha3;
use signature::Keypair;

use crate::algorithms::{Ed25519Derivation, KeyDerivation, Secp256k1Derivation};
use crate::constants::*;
use crate::error::CryptoError;
use crate::{Algorithm, AnyPrivateKey, AnyPublicKey};

/// Derive a seed from a passphrase using PBKDF2 with SHA3-256.
///
/// This function applies PBKDF2 key derivation to convert a passphrase
/// into a 32-byte seed suitable for key derivation.
pub fn seed_from_passphrase(passphrase: &str) -> Result<SecretBox<[u8; 32]>, CryptoError> {
	// Normalize passphrase (lowercase, remove spaces) to match accounts crate behavior
	let clean_passphrase = passphrase.to_lowercase().replace(" ", "");
	let clean_passphrase_buffer = clean_passphrase.as_bytes();

	if clean_passphrase_buffer.len() < MIN_PASSPHRASE_LENGTH {
		return Err(CryptoError::InvalidInput);
	}

	let mut key = [0u8; 32];

	// Use PBKDF2 with SHA3-256, 64000 iterations, using passphrase as both input and salt
	pbkdf2::pbkdf2_hmac::<sha3::Sha3_256>(
		clean_passphrase_buffer,
		clean_passphrase_buffer,
		PBKDF2_ITERATIONS,
		&mut key,
	);

	Ok(SecretBox::new(Box::new(key)))
}

/// Generates a random 24-word passphrase using a specified dictionary.
/// The default is the English dictionary.
/// Returns an error if the OS RNG fails.
pub fn generate_random_passphrase(
	dictionary: Option<DefaultDictionary>,
) -> Result<SecretBox<Vec<String>>, CryptoError> {
	let words = dictionary.unwrap_or(bip39_dict::ENGLISH).words;
	let word_count = words.len() as u32;
	let passphrase: Result<Vec<String>, CryptoError> = (0..24)
		.map(|_| {
			let idx = rand_core::OsRng
				.try_next_u32()
				.map_err(|_| CryptoError::InternalError { message: "Failed to generate random number".to_string() })?;
			let word = words[(idx % word_count) as usize];

			String::from_str(word)
				.map_err(|_| CryptoError::InternalError { message: "Failed to convert word to string".to_string() })
		})
		.collect();

	Ok(SecretBox::new(Box::new(passphrase?)))
}

/// Generates a random 32-byte seed using the OS RNG.
/// Returns an error if the OS RNG fails.
pub fn generate_random_seed() -> Result<SecretBox<[u8; 32]>, CryptoError> {
	let mut seed_buffer = [0u8; 32];

	rand_core::OsRng
		.try_fill_bytes(&mut seed_buffer)
		.map_err(|_| CryptoError::InternalError { message: "Failed to generate random seed".to_string() })?;

	Ok(SecretBox::new(Box::new(seed_buffer)))
}

/// Create a key pair for the specified algorithm
pub fn create_keypair_from_seed(
	seed: &[u8],
	algorithm: Algorithm,
) -> Result<(AnyPrivateKey, AnyPublicKey), CryptoError> {
	match algorithm {
		Algorithm::Secp256k1 => {
			let private_key = Secp256k1Derivation::derive_from_seed(seed)?;
			let public_key = private_key.verifying_key();

			Ok((AnyPrivateKey::Secp256k1(private_key), AnyPublicKey::Secp256k1(public_key)))
		}
		Algorithm::Ed25519 => {
			let private_key = Ed25519Derivation::derive_from_seed(seed)?;
			let public_key = private_key.verifying_key();

			Ok((AnyPrivateKey::Ed25519(private_key), AnyPublicKey::Ed25519(public_key)))
		}
		Algorithm::Secp256r1 => {
			Err(CryptoError::UnsupportedAlgorithm { algorithm: "secp256r1 not implemented".to_string() })
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use secrecy::ExposeSecret;

	#[test]
	fn test_seed_from_passphrase() {
		let passphrase = "panic category office glow ski camera file slight room escape indicate fiction";

		let seed = seed_from_passphrase(passphrase);
		assert!(seed.is_ok());

		let seed = seed.unwrap();
		assert_eq!(seed.expose_secret().len(), 32);
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
	fn test_create_keypair_from_seed() {
		let seed = b"test seed for keypair creation!!!!!";

		// Test secp256k1 creation
		let (private_key, public_key) = create_keypair_from_seed(seed, crate::Algorithm::Secp256k1).unwrap();
		assert_eq!(crate::Algorithm::from(&private_key), crate::Algorithm::Secp256k1);
		assert_eq!(crate::Algorithm::from(&public_key), crate::Algorithm::Secp256k1);

		// Test Ed25519 creation
		let (private_key, public_key) = create_keypair_from_seed(seed, crate::Algorithm::Ed25519).unwrap();
		assert_eq!(crate::Algorithm::from(&private_key), crate::Algorithm::Ed25519);
		assert_eq!(crate::Algorithm::from(&public_key), crate::Algorithm::Ed25519);

		// Test unsupported algorithm
		let result = create_keypair_from_seed(seed, crate::Algorithm::Secp256r1);
		assert!(result.is_err());
	}
}
