use core::str::FromStr;

use bip39_dict::DefaultDictionary;
use pbkdf2;
use rand_core::TryRngCore;
use secrecy::SecretBox;
use sha3;

use crate::algorithms::{Ed25519Derivation, KeyDerivation, PrivateKey, Secp256k1Derivation};
use crate::constants::*;
use crate::error::CryptoError;
use crate::{Algorithm, AnyPrivateKey, AnyPublicKey};

// Helper functions for error creation
// Note: These are necessary for test coverage
fn create_rng_error() -> CryptoError {
	CryptoError::InternalError { message: "Failed to generate random number".to_string() }
}

fn create_string_conversion_error() -> CryptoError {
	CryptoError::InternalError { message: "Failed to convert word to string".to_string() }
}

fn create_seed_generation_error() -> CryptoError {
	CryptoError::InternalError { message: "Failed to generate random seed".to_string() }
}

/// Derive a seed from a passphrase using PBKDF2 with SHA3-256.
///
/// This function applies PBKDF2 key derivation to convert a passphrase
/// into a 32-byte seed suitable for key derivation.
pub fn seed_from_passphrase(passphrase: &str) -> Result<SecretBox<[u8; 32]>, CryptoError> {
	// Normalize passphrase (lowercase, remove spaces)
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
				.map_err(|_| create_rng_error())?;
			let word = words[(idx % word_count) as usize];

			String::from_str(word).map_err(|_| create_string_conversion_error())
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
		.map_err(|_| create_seed_generation_error())?;

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
			let public_key = private_key.as_public_key();

			Ok((AnyPrivateKey::Secp256k1(private_key), AnyPublicKey::Secp256k1(public_key)))
		}
		Algorithm::Ed25519 => {
			let private_key = Ed25519Derivation::derive_from_seed(seed)?;
			let public_key = private_key.as_public_key();

			Ok((AnyPrivateKey::Ed25519(private_key), AnyPublicKey::Ed25519(public_key)))
		}
		Algorithm::Secp256r1 => {
			Err(CryptoError::UnsupportedAlgorithm { algorithm: "secp256r1 not implemented".to_string() })
		}
	}
}

/// Parse DER-encoded ECDSA signature to extract r,s components.
///
/// DER format: SEQUENCE { r INTEGER, s INTEGER }
/// This matches the TypeScript signatureFromDERRaw implementation
/// and converts to exactly 32-byte arrays for secp256r1/secp256k1 compatibility.
///
/// This function is only available when the "der" feature is enabled.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "der")]
/// # {
/// use crypto::utils::parse_der_ecdsa_signature;
///
/// // Example DER-encoded ECDSA signature (minimal valid structure)
/// let der_sig = &[
///     0x30, 0x44,             // SEQUENCE, 68 bytes
///     0x02, 0x20,             // INTEGER, 32 bytes (r)
///     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
///     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
///     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
///     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
///     0x02, 0x20,             // INTEGER, 32 bytes (s)
///     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
///     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
///     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
///     0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
/// ];
///
/// let (r, s) = parse_der_ecdsa_signature(der_sig).unwrap();
/// assert_eq!(r.len(), 32);
/// assert_eq!(s.len(), 32);
/// # }
/// ```
#[cfg(feature = "der")]
pub fn parse_der_ecdsa_signature(der_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
	if der_bytes.len() < 8 || der_bytes[0] != 0x30 {
		return Err(CryptoError::InvalidInput);
	}

	let seq_len = der_bytes[1] as usize;
	if seq_len + 2 > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}

	let mut pos = 2;

	// Parse r INTEGER
	if pos >= der_bytes.len() || der_bytes[pos] != 0x02 {
		return Err(CryptoError::InvalidInput);
	}
	pos += 1;

	if pos >= der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}
	let r_len = der_bytes[pos] as usize;
	pos += 1;

	if pos + r_len > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}
	let r_bytes = &der_bytes[pos..pos + r_len];
	pos += r_len;

	// Parse s INTEGER
	if pos >= der_bytes.len() || der_bytes[pos] != 0x02 {
		return Err(CryptoError::InvalidInput);
	}
	pos += 1;

	if pos >= der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}
	let s_len = der_bytes[pos] as usize;
	pos += 1;

	if pos + s_len > der_bytes.len() {
		return Err(CryptoError::InvalidInput);
	}
	let s_bytes = &der_bytes[pos..pos + s_len];

	// Convert to exactly 32-byte arrays like TypeScript does
	let mut r_array = [0u8; 32];
	let mut s_array = [0u8; 32];

	// Handle r value: truncate from left if > 32 bytes, pad on left if < 32 bytes
	if r_bytes.len() > 32 {
		// TypeScript: sigSECValue.slice(-32) - take last 32 bytes
		r_array.copy_from_slice(&r_bytes[r_bytes.len() - 32..]);
	} else {
		// Pad on the left with zeros
		let start = 32 - r_bytes.len();
		r_array[start..].copy_from_slice(r_bytes);
	}

	// Handle s value: truncate from left if > 32 bytes, pad on left if < 32 bytes
	if s_bytes.len() > 32 {
		// TypeScript: sigSECValue.slice(-32) - take last 32 bytes
		s_array.copy_from_slice(&s_bytes[s_bytes.len() - 32..]);
	} else {
		// Pad on the left with zeros
		let start = 32 - s_bytes.len();
		s_array[start..].copy_from_slice(s_bytes);
	}

	Ok((r_array, s_array))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Algorithm;
	use secrecy::ExposeSecret;

	#[test]
	fn test_seed_from_passphrase() {
		let passphrase = "panic category office glow ski camera file slight room escape indicate fiction";

		let seed = seed_from_passphrase(passphrase);
		assert!(seed.is_ok());

		let seed = seed.unwrap();
		assert_eq!(seed.expose_secret().len(), 32);

		// Test with passphrase shorter than MIN_PASSPHRASE_LENGTH (60 characters)
		let short_passphrase = "short"; // Only 5 characters
		let result = seed_from_passphrase(short_passphrase);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidInput));

		// Test with passphrase that's just under the limit
		let almost_long_passphrase = "a".repeat(59); // 59 characters, 1 under limit
		let result = seed_from_passphrase(&almost_long_passphrase);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidInput));

		// Test with passphrase that meets the minimum length
		let min_length_passphrase = "a".repeat(60); // Exactly 60 characters
		let result = seed_from_passphrase(&min_length_passphrase);
		assert!(result.is_ok());

		// Test that spaces are removed and lowercase is applied
		let passphrase_with_spaces = "PANIC CATEGORY OFFICE GLOW SKI CAMERA FILE SLIGHT ROOM ESCAPE INDICATE FICTION";
		// cspell:disable-next-line
		let normalized_passphrase = "paniccategoryofficeglowskicamerafileslightroomescapeindicatefiction";

		let seed1 = seed_from_passphrase(passphrase_with_spaces).unwrap();
		let seed2 = seed_from_passphrase(normalized_passphrase).unwrap();

		// Both should produce the same result
		assert_eq!(seed1.expose_secret(), seed2.expose_secret());
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
		let (private_key, public_key) = create_keypair_from_seed(seed, Algorithm::Secp256k1).unwrap();
		assert_eq!(Algorithm::from(&private_key), Algorithm::Secp256k1);
		assert_eq!(Algorithm::from(&public_key), Algorithm::Secp256k1);

		// Test Ed25519 creation
		let (private_key, public_key) = create_keypair_from_seed(seed, Algorithm::Ed25519).unwrap();
		assert_eq!(Algorithm::from(&private_key), Algorithm::Ed25519);
		assert_eq!(Algorithm::from(&public_key), Algorithm::Ed25519);

		// Test unsupported algorithm
		let result = create_keypair_from_seed(seed, Algorithm::Secp256r1);
		assert!(result.is_err());
	}

	#[test]
	fn test_error_creation_functions() {
		// Test that error creation functions work correctly and return InternalError variants
		assert!(matches!(create_rng_error(), CryptoError::InternalError { .. }));
		assert!(matches!(create_seed_generation_error(), CryptoError::InternalError { .. }));
		assert!(matches!(create_string_conversion_error(), CryptoError::InternalError { .. }));
	}

	#[test]
	#[cfg(feature = "der")]
	fn test_parse_der_ecdsa_signature() {
		// Valid DER-encoded ECDSA signature
		let valid_der = [
			0x30, 0x44, // SEQUENCE, length 68
			0x02, 0x20, // INTEGER, length 32 (r)
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
			0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x02,
			0x20, // INTEGER, length 32 (s)
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
			0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
		];

		let result = parse_der_ecdsa_signature(&valid_der);
		assert!(result.is_ok());

		let (r, s) = result.unwrap();
		assert_eq!(r.len(), 32);
		assert_eq!(s.len(), 32);

		// Check that r and s values are correctly extracted
		assert_eq!(r[0], 0x01);
		assert_eq!(r[31], 0x20);
		assert_eq!(s[0], 0x21);
		assert_eq!(s[31], 0x40);

		// Test invalid cases
		assert!(parse_der_ecdsa_signature(&[]).is_err()); // Empty input
		assert!(parse_der_ecdsa_signature(&[0x31, 0x44]).is_err()); // Wrong tag
		assert!(parse_der_ecdsa_signature(&[0x30, 0x44]).is_err()); // Too short
		assert!(parse_der_ecdsa_signature(&[0x30, 0x02, 0x05]).is_err()); // Invalid structure
	}
}
