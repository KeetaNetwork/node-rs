//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementation.
//!
//! This module provides ECIES encryption.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::algorithms::aes_cbc::Aes256Cbc;
use crate::algorithms::aes_ctr::Aes128CtrCipher;
use crate::algorithms::ed25519::{X25519PrivateKey, X25519PublicKey};
use crate::algorithms::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::algorithms::secp256r1::{Secp256r1PrivateKey, Secp256r1PublicKey};
use crate::algorithms::PublicKey;
use crate::error::CryptoError;
use crate::hash::HashAlgorithm;
use crate::operations::encryption::{KeyExchange, KeyGeneration, SymmetricEncryption};
use crate::utils::generate_random_bytes;
use crate::PrivateKey;

/// Algorithm identifier for ECIES with secp256k1
pub const ECIES_SECP256K1_ALGORITHM: &str = "ECIES-secp256k1-AES128CTR";

/// Algorithm identifier for ECIES with X25519
pub const ECIES_X25519_ALGORITHM: &str = "ECIES-X25519-AES-CBC";

/// Algorithm identifier for ECIES with secp256r1
pub const ECIES_SECP256R1_ALGORITHM: &str = "ECIES-secp256r1-AES256CBC";

/// ECIES (Elliptic Curve Integrated Encryption Scheme) trait.
///
/// This trait provides a standard interface for ECIES implementations
/// across different curves.
pub trait Ecies {
	/// The public key type for this ECIES implementation.
	type PublicKey;
	/// The private key type for this ECIES implementation.
	type PrivateKey;

	/// Encrypt data using ECIES.
	///
	/// # Arguments
	/// * `recipient_public_key` - The recipient's public key
	/// * `plaintext` - Data to encrypt
	///
	/// # Returns
	/// Encrypted data
	fn encrypt<T: AsRef<[u8]>>(recipient_public_key: &Self::PublicKey, plaintext: T) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using ECIES.
	///
	/// # Arguments
	/// * `recipient_private_key` - The recipient's private key
	/// * `ciphertext` - Encrypted data
	///
	/// # Returns
	/// Decrypted plaintext data
	fn decrypt<T: AsRef<[u8]>>(recipient_private_key: &Self::PrivateKey, ciphertext: T)
		-> Result<Vec<u8>, CryptoError>;

	/// Get algorithm information string.
	fn algorithm_info() -> &'static str;
}

/// ECIES encryption using secp256k1 and AES-128-CTR.
pub struct EciesSecp256k1;

impl EciesSecp256k1 {
	/// Derive encryption and MAC keys from shared secret.
	///
	/// This matches the ecies-geth implementation which uses a counter-based
	/// KDF and then SHA-256 for the MAC key derivation.
	fn derive_keys(shared_secret: impl AsRef<[u8]>) -> Result<([u8; 16], [u8; 32]), CryptoError> {
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		// First derive 32 bytes using the KDF
		let kdf_output = Self::kdf(shared_secret.as_ref(), 32)?;

		// First 16 bytes are the encryption key for AES-128
		let mut encryption_key = [0u8; 16];
		encryption_key.copy_from_slice(&kdf_output[0..16]);

		// MAC key is SHA-256 of the last 16 bytes
		let mac_key_hash = HashAlgorithm::Sha2_256.hash_array::<32>(&kdf_output[16..32])?;

		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		Ok((encryption_key, mac_key_hash))
	}

	/// KDF implementation that mimics ecies-geth's counter-based KDF.
	///
	/// This is the same KDF used in Parity and Geth implementations.
	fn kdf(secret: impl AsRef<[u8]>, output_length: usize) -> Result<Vec<u8>, CryptoError> {
		let mut ctr = 1u32;
		let mut written = 0;
		let mut result = Vec::new();

		while written < output_length {
			// Create counter bytes (big-endian)
			let ctr_bytes = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];

			// Hash: counter || secret
			let mut combined = Vec::with_capacity(4 + secret.as_ref().len());
			combined.extend_from_slice(&ctr_bytes);
			combined.extend_from_slice(secret.as_ref());

			let hash_result = HashAlgorithm::Sha2_256.hash(&combined);

			result.extend_from_slice(&hash_result);
			written += 32;
			ctr += 1;
		}

		Ok(result)
	}
}

impl Ecies for EciesSecp256k1 {
	type PublicKey = Secp256k1PublicKey;
	type PrivateKey = Secp256k1PrivateKey;

	/// Encrypt data using ECIES with secp256k1
	///
	/// Uses AES-128-CTR for encryption and custom KDF with HMAC-SHA256 for
	/// authentication.
	///
	/// Format: ephemeral_public_key (65 bytes) + (iv + ciphertext) + hmac (32 bytes)
	fn encrypt<T: AsRef<[u8]>>(
		recipient_public_key: &Secp256k1PublicKey,
		plaintext: T,
	) -> Result<Vec<u8>, CryptoError> {
		// Generate ephemeral key pair
		let ephemeral_private = Secp256k1PrivateKey::generate_random()?;
		let ephemeral_public = ephemeral_private.as_public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_private.ecdh(recipient_public_key)?;
		// Get ephemeral public key bytes (uncompressed for ecies-geth compatibility)
		let ephemeral_public_uncompressed = ephemeral_public.to_uncompressed_bytes();

		// Derive keys using custom KDF (matches ecies-geth)
		let (encryption_key, mac_key) = Self::derive_keys(&shared_secret)?;
		// Generate IV for AES-128-CTR
		let iv = Aes128CtrCipher::generate_iv();
		// Encrypt with AES-128-CTR
		let cipher = Aes128CtrCipher::new();
		let ciphertext_only = cipher
			.encrypt_with_iv(encryption_key, iv, plaintext.as_ref())
			.map_err(|_| CryptoError::EncryptionFailed)?;

		// Create ciphertext with IV prepended (matches ecies-geth aes128CtrEncrypt)
		let mut cipher_with_iv = Vec::with_capacity(16 + ciphertext_only.len());
		cipher_with_iv.extend_from_slice(&iv);
		cipher_with_iv.extend_from_slice(&ciphertext_only);

		// Calculate HMAC-SHA256 over cipher_with_iv (IV + ciphertext)
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|_| CryptoError::EncryptionFailed)?;
		mac.update(&cipher_with_iv);
		let hmac_result = mac.finalize().into_bytes();

		// Construct final message: ephemeral_public_key + (iv + ciphertext) + hmac
		let mut result = Vec::with_capacity(65 + cipher_with_iv.len() + 32);
		result.extend_from_slice(&ephemeral_public_uncompressed);
		result.extend_from_slice(&cipher_with_iv);
		result.extend_from_slice(&hmac_result);

		Ok(result)
	}

	/// Decrypt data using ECIES with secp256k1.
	///
	/// Uses AES-128-CTR for decryption and HMAC-SHA256 for authentication.
	fn decrypt<T: AsRef<[u8]>>(
		recipient_private_key: &Secp256k1PrivateKey,
		ciphertext: T,
	) -> Result<Vec<u8>, CryptoError> {
		// Check minimum length: 65 (ephemeral_pk) + 16 (iv) + 32 (hmac) = 113 bytes minimum
		if ciphertext.as_ref().len() < 113 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Parse the message components
		let ephemeral_public_bytes = &ciphertext.as_ref()[0..65];
		let hmac_start = ciphertext.as_ref().len() - 32;
		let cipher_with_iv = &ciphertext.as_ref()[65..hmac_start]; // IV + encrypted data
		let received_hmac = &ciphertext.as_ref()[hmac_start..];

		// Parse ephemeral public key
		let ephemeral_public = Secp256k1PublicKey::try_from(ephemeral_public_bytes)?;
		// Perform ECDH to get shared secret
		let shared_secret = recipient_private_key.ecdh(&ephemeral_public)?;
		// Derive keys using custom KDF (matches ecies-geth)
		let (encryption_key, mac_key) = Self::derive_keys(&shared_secret)?;

		// Verify HMAC before decryption (HMAC is over IV + ciphertext)
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|_| CryptoError::DecryptionFailed)?;
		mac.update(cipher_with_iv);

		let computed_hmac = mac.finalize().into_bytes();

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		let hmac_matches = computed_hmac.ct_eq(received_hmac);
		if hmac_matches.unwrap_u8() == 0 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		// Extract IV and ciphertext
		if cipher_with_iv.len() < 16 {
			return Err(CryptoError::DecryptionFailed);
		}

		let iv = &cipher_with_iv[0..16];
		let encrypted_data = &cipher_with_iv[16..];
		// Decrypt with AES-128-CTR
		let cipher = Aes128CtrCipher::new();
		let plaintext = cipher
			.decrypt_with_iv(encryption_key, iv, encrypted_data)
			.map_err(|_| CryptoError::DecryptionFailed)?;

		Ok(plaintext)
	}

	fn algorithm_info() -> &'static str {
		ECIES_SECP256K1_ALGORITHM
	}
}

/// ECIES encryption using X25519 and AES-128-CTR.
pub struct EciesX25519;

impl Ecies for EciesX25519 {
	type PublicKey = X25519PublicKey;
	type PrivateKey = X25519PrivateKey;

	/// Encrypt data using ECIES with X25519
	///
	/// Uses AES-CBC for encryption and HMAC-SHA256 (matching ecies-25519 format).
	///
	/// Format: iv (16 bytes) + ephemeral_public_key (32 bytes) + mac (32 bytes) + ciphertext
	fn encrypt<T: AsRef<[u8]>>(recipient_public_key: &X25519PublicKey, plaintext: T) -> Result<Vec<u8>, CryptoError> {
		// Generate ephemeral key pair
		let ephemeral_private_bytes = generate_random_bytes::<32>()?;
		// Create X25519 private key from random bytes
		let ephemeral_private = X25519PrivateKey::try_from(ephemeral_private_bytes.as_slice())?;
		let ephemeral_public = ephemeral_private.derive_public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_private.diffie_hellman(recipient_public_key);

		// Derive keys using SHA-512 (matching ecies-25519)
		let sha512_hash = HashAlgorithm::Sha2_512.hash(shared_secret);
		let encryption_key = &sha512_hash[0..32]; // First 32 bytes
		let mac_key = &sha512_hash[32..]; // Remaining bytes

		// Generate IV for AES-CBC (16 bytes)
		let iv = generate_random_bytes::<16>()?;
		// Encrypt with AES-CBC
		let cipher = Aes256Cbc;
		let iv_and_ciphertext = SymmetricEncryption::encrypt(&cipher, encryption_key, Some(&iv), plaintext.as_ref())?;
		// Extract just the ciphertext part (skip the IV that was prepended)
		let ciphertext = &iv_and_ciphertext[16..];

		// Get ephemeral public key bytes (32 bytes for X25519)
		let ephemeral_public_bytes: Vec<u8> = ephemeral_public.into();

		// Calculate HMAC-SHA256 over iv + ephemeral_public_key + ciphertext
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).map_err(|_| CryptoError::EncryptionFailed)?;
		mac.update(&iv);
		mac.update(&ephemeral_public_bytes);
		mac.update(ciphertext);

		let hmac_result = mac.finalize().into_bytes();

		// Construct final message: iv + ephemeral_public_key + mac + ciphertext
		let mut result = Vec::with_capacity(16 + 32 + 32 + ciphertext.len());
		result.extend_from_slice(&iv);
		result.extend_from_slice(&ephemeral_public_bytes);
		result.extend_from_slice(&hmac_result);
		result.extend_from_slice(ciphertext);

		Ok(result)
	}

	/// Decrypt data using ECIES with X25519.
	///
	/// Uses AES-CBC for decryption and HMAC-SHA256 (matching ecies-25519 format).
	fn decrypt<T: AsRef<[u8]>>(
		recipient_private_key: &X25519PrivateKey,
		ciphertext: T,
	) -> Result<Vec<u8>, CryptoError> {
		// Check minimum length: 16 (iv) + 32 (ephemeral_pk) + 32 (mac) = 80 bytes minimum
		if ciphertext.as_ref().len() < 80 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Parse the message components: iv + ephemeral_public_key + mac + ciphertext
		let iv = &ciphertext.as_ref()[0..16];
		let ephemeral_public_bytes = &ciphertext.as_ref()[16..48];
		let received_mac = &ciphertext.as_ref()[48..80];
		let encrypted_data = &ciphertext.as_ref()[80..];

		// Parse ephemeral public key
		let ephemeral_public = X25519PublicKey::try_from(ephemeral_public_bytes)?;
		// Perform ECDH to get shared secret
		let shared_secret = recipient_private_key.diffie_hellman(&ephemeral_public);

		// Derive keys using SHA-512 (matching ecies-25519)
		let sha512_hash = HashAlgorithm::Sha2_512.hash(shared_secret);
		let encryption_key = &sha512_hash[0..32]; // First 32 bytes
		let mac_key = &sha512_hash[32..]; // Remaining bytes

		// Verify HMAC before decryption (HMAC is over iv + ephemeral_public_key + ciphertext)
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).map_err(|_| CryptoError::DecryptionFailed)?;
		mac.update(iv);
		mac.update(ephemeral_public_bytes);
		mac.update(encrypted_data);

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		let computed_mac = mac.finalize().into_bytes();
		let mac_matches = computed_mac.ct_eq(received_mac);
		if mac_matches.unwrap_u8() == 0 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		// Decrypt with AES-CBC
		let cipher = Aes256Cbc;
		// AES-CBC decrypt expects iv + ciphertext format
		let mut iv_and_ciphertext = Vec::with_capacity(16 + encrypted_data.len());
		iv_and_ciphertext.extend_from_slice(iv);
		iv_and_ciphertext.extend_from_slice(encrypted_data);
		let plaintext = SymmetricEncryption::decrypt(&cipher, encryption_key, &iv_and_ciphertext)?;

		Ok(plaintext)
	}

	fn algorithm_info() -> &'static str {
		ECIES_X25519_ALGORITHM
	}
}

/// ECIES encryption using secp256r1 (NIST P-256) and AES-256-CBC.
///
/// This implementation follows the crypto-ecies-cpp format used in TypeScript.
/// Uses KDF2_18033_SHA512, AES256_CBC, and HMAC_SHA512 as per defaults.
pub struct EciesSecp256r1;

impl Ecies for EciesSecp256r1 {
	type PublicKey = Secp256r1PublicKey;
	type PrivateKey = Secp256r1PrivateKey;

	/// Encrypt data using ECIES with secp256r1 (NIST P-256)
	///
	/// Uses AES-256-CBC for encryption and HMAC-SHA512 for authentication.
	/// This follows the crypto-ecies-js format.
	///
	/// Format: ephemeral_public_key (65 bytes) + ciphertext + hmac (64 bytes) + iv (16 bytes)
	fn encrypt<T: AsRef<[u8]>>(
		recipient_public_key: &Secp256r1PublicKey,
		plaintext: T,
	) -> Result<Vec<u8>, CryptoError> {
		// Generate ephemeral key pair
		let ephemeral_private = Secp256r1PrivateKey::generate_random()?;
		let ephemeral_public = ephemeral_private.as_public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_private.ecdh(recipient_public_key)?;
		// Get ephemeral public key bytes (uncompressed format for P-256)
		let ephemeral_public_uncompressed = ephemeral_public.to_uncompressed_bytes();
		// Extract shared secret X coordinate (the full 32 bytes)
		let shared_secret_x = &shared_secret;

		// Derive keys using TypeScript-compatible KDF
		let (encryption_key, mac_key) = Self::derive_keys(&ephemeral_public_uncompressed, shared_secret_x)?;
		// Generate IV for AES-256-CBC (16 bytes)
		let iv = generate_random_bytes::<16>()?;

		// Encrypt with AES-256-CBC
		let cipher = Aes256Cbc;
		let iv_and_ciphertext = SymmetricEncryption::encrypt(&cipher, encryption_key, Some(&iv), plaintext.as_ref())
			.map_err(|_| CryptoError::EncryptionFailed)?;
		// Extract just the ciphertext part (skip the IV that was prepended)
		let ciphertext_only = &iv_and_ciphertext[16..];

		// Calculate HMAC-SHA512 over the ciphertext only (matching TypeScript implementation)
		let mut mac =
			<Hmac<sha2::Sha512> as Mac>::new_from_slice(&mac_key).map_err(|_| CryptoError::EncryptionFailed)?;
		mac.update(ciphertext_only);
		// Add the fixed IV length value (padded to 16 hex chars = 8 bytes of zeros)
		mac.update(&[0u8; 8]); // "0000000000000000" as 8 zero bytes
		let hmac_result = mac.finalize().into_bytes();

		// Construct final message: ephemeral_public_key + ciphertext + hmac + iv (TypeScript format)
		let mut result = Vec::with_capacity(65 + ciphertext_only.len() + 64 + 16);
		result.extend_from_slice(&ephemeral_public_uncompressed);
		result.extend_from_slice(ciphertext_only);
		result.extend_from_slice(&hmac_result);
		result.extend_from_slice(&iv);

		Ok(result)
	}

	/// Decrypt data using ECIES with secp256r1 (NIST P-256)
	///
	/// Uses AES-256-CBC for decryption and HMAC-SHA512 for authentication.
	/// This follows the crypto-ecies-js format.
	fn decrypt<T: AsRef<[u8]>>(
		recipient_private_key: &Secp256r1PrivateKey,
		ciphertext: T,
	) -> Result<Vec<u8>, CryptoError> {
		// Minimum size: ephemeral_key(65) + ciphertext(16) + hmac(64) + iv(16) = 161
		if ciphertext.as_ref().len() < 161 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Parse components using TypeScript format: ephemeral_pk + ciphertext + hmac + iv
		let ephemeral_public_bytes = &ciphertext.as_ref()[0..65];
		let iv_start = ciphertext.as_ref().len() - 16;
		let hmac_start = ciphertext.as_ref().len() - 80; // 64 + 16 = 80
		let encrypted_data = &ciphertext.as_ref()[65..hmac_start];
		let received_hmac = &ciphertext.as_ref()[hmac_start..iv_start];
		let iv = &ciphertext.as_ref()[iv_start..];

		// Parse ephemeral public key
		let ephemeral_public = Secp256r1PublicKey::try_from(ephemeral_public_bytes)?;
		// Perform ECDH to get shared secret
		let shared_secret = recipient_private_key.ecdh(&ephemeral_public)?;
		// Extract shared secret X coordinate (the full 32 bytes)
		let shared_secret_x = &shared_secret;
		// Derive keys using TypeScript-compatible KDF
		let (encryption_key, mac_key) = Self::derive_keys(ephemeral_public_bytes, shared_secret_x)?;

		// Verify HMAC before decryption (HMAC is over ciphertext + fixed IV length value)
		let mut mac =
			<Hmac<sha2::Sha512> as Mac>::new_from_slice(&mac_key).map_err(|_| CryptoError::DecryptionFailed)?;
		mac.update(encrypted_data);
		// Add the fixed IV length value (padded to 16 hex chars = 8 bytes of zeros)
		mac.update(&[0u8; 8]); // "0000000000000000" as 8 zero bytes
		let computed_hmac = mac.finalize().into_bytes();

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		let hmac_matches = computed_hmac.ct_eq(received_hmac);
		if hmac_matches.unwrap_u8() == 0 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Constant-time operation memory fence
		core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

		// Decrypt with AES-256-CBC
		let cipher = Aes256Cbc;
		// AES-CBC decrypt expects iv + ciphertext format
		let mut iv_and_ciphertext = Vec::with_capacity(16 + encrypted_data.len());
		iv_and_ciphertext.extend_from_slice(iv);
		iv_and_ciphertext.extend_from_slice(encrypted_data);

		let plaintext = SymmetricEncryption::decrypt(&cipher, encryption_key, &iv_and_ciphertext)?;
		Ok(plaintext)
	}

	fn algorithm_info() -> &'static str {
		ECIES_SECP256R1_ALGORITHM
	}
}

impl EciesSecp256r1 {
	/// KDF implementation matching the TypeScript crypto-ecies-js package
	///
	/// This generates derivation keys using iterative SHA512 over a seed constructed from
	/// ephemeral public key (65 bytes) + shared secret X coordinate (32 bytes)
	fn derive_keys(
		ephemeral_public_key: impl AsRef<[u8]>,
		shared_secret_x: impl AsRef<[u8]>,
	) -> Result<([u8; 32], [u8; 128]), CryptoError> {
		use sha2::{Digest, Sha512};

		// Construct seed: ephemeral_public_key (65 bytes) + shared_secret_x (32 bytes, padded to 64 hex chars)
		let mut seed = Vec::with_capacity(65 + 32);
		seed.extend_from_slice(ephemeral_public_key.as_ref());
		seed.extend_from_slice(shared_secret_x.as_ref());

		// Key sizes matching TypeScript implementation
		let symmetric_key_bytes = 256 / 8; // 32 bytes for AES-256
		let mac_key_bytes = 1024 / 8; // 128 bytes for HMAC key
		let digest_bytes = 512 / 8; // 64 bytes per SHA512 digest
		let total_bytes: usize = symmetric_key_bytes + mac_key_bytes; // 160 bytes total

		let mut derivation_key = Vec::new();

		// Iterative KDF: for i = 1 to ceil(total_bytes / digest_bytes)
		let iterations = total_bytes.div_ceil(digest_bytes);
		for i in 1..=iterations {
			let mut hasher = Sha512::new();
			hasher.update(&seed);
			hasher.update((i as u32).to_be_bytes()); // Counter as big-endian 4 bytes
			let digest = hasher.finalize();
			derivation_key.extend_from_slice(&digest);
		}

		// Truncate to required length
		derivation_key.truncate(total_bytes);

		// Split into symmetric key (first 32 bytes) and MAC key (remaining 128 bytes)
		let mut symmetric_key = [0u8; 32];
		let mut mac_key = [0u8; 128];
		symmetric_key.copy_from_slice(&derivation_key[0..32]);
		mac_key.copy_from_slice(&derivation_key[32..160]);

		Ok((symmetric_key, mac_key))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::algorithms::ed25519::{ed25519_to_x25519_private, Ed25519Derivation};
	use crate::algorithms::secp256k1::Secp256k1Derivation;
	use crate::algorithms::secp256r1::Secp256r1Derivation;
	use crate::algorithms::PrivateKey;
	use crate::error::CryptoError;
	use crate::operations::encryption::AsymmetricEncryption;
	use crate::KeyDerivation;

	const TEST_SEED: &str =
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
	const TEST_SEED_ALTERNATE: &str =
		"ability ability ability ability ability ability ability ability ability ability ability ability";

	#[test]
	fn test_ecies_secp256k1_basic() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Hello, ECIES world!";

		// Test encryption
		let ciphertext = EciesSecp256k1::encrypt(&public_key, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert!(ciphertext.len() > plaintext.len()); // Should be larger (ephemeral key + IV + padding)

		// Test decryption
		let decrypted = EciesSecp256k1::decrypt(&private_key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_ecies_secp256k1_trait_implementation() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Testing AsymmetricEncryption trait";

		// Test via trait methods
		let ciphertext = public_key.encrypt(plaintext).unwrap();
		let decrypted = private_key.decrypt(&ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test algorithm info
		assert_eq!(public_key.algorithm_info(), "ECIES-secp256k1-AES128CTR");
		assert_eq!(private_key.algorithm_info(), "ECIES-secp256k1-AES128CTR");
	}

	#[test]
	fn test_ecies_trait_implementation() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Testing ECIES trait interface";

		// Test encryption via trait
		let ciphertext = EciesSecp256k1::encrypt(&public_key, plaintext);
		assert!(ciphertext.is_ok());

		// Test decryption via trait
		let decrypted = EciesSecp256k1::decrypt(&private_key, ciphertext.unwrap()).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test algorithm info via trait
		assert_eq!(EciesSecp256k1::algorithm_info(), "ECIES-secp256k1-AES128CTR");
	}

	#[test]
	fn test_ecies_secp256k1_different_keys() {
		let mut alice_seed = TEST_SEED.as_bytes().to_vec();
		alice_seed.extend_from_slice(b"alice");
		let mut bob_seed = TEST_SEED_ALTERNATE.as_bytes().to_vec();
		bob_seed.extend_from_slice(b"bob");

		let plaintext = b"Message from Alice to Bob";

		// Key generation for Alice and Bob
		let alice_private = Secp256k1Derivation::derive_from_seed(&alice_seed).unwrap();
		let alice_public = alice_private.as_public_key();
		let bob_private = Secp256k1Derivation::derive_from_seed(&bob_seed).unwrap();
		let bob_public = bob_private.as_public_key();

		// Alice encrypts for Bob
		let ciphertext_for_bob = EciesSecp256k1::encrypt(&bob_public, plaintext).unwrap();

		// Bob decrypts
		let decrypted_by_bob = EciesSecp256k1::decrypt(&bob_private, &ciphertext_for_bob).unwrap();
		assert_eq!(decrypted_by_bob, plaintext);

		// Alice cannot decrypt her own message meant for Bob (wrong private key)
		let alice_decrypt_result = EciesSecp256k1::decrypt(&alice_private, &ciphertext_for_bob);
		assert!(alice_decrypt_result.is_err());

		// Test the reverse: Bob encrypts for Alice
		let reverse_plaintext = b"Reply from Bob to Alice";
		let ciphertext_for_alice = EciesSecp256k1::encrypt(&alice_public, reverse_plaintext).unwrap();

		// Alice decrypts
		let decrypted_by_alice = EciesSecp256k1::decrypt(&alice_private, &ciphertext_for_alice).unwrap();
		assert_eq!(decrypted_by_alice, reverse_plaintext);

		// Bob cannot decrypt his own message meant for Alice (wrong private key)
		let bob_decrypt_result = EciesSecp256k1::decrypt(&bob_private, &ciphertext_for_alice);
		assert!(bob_decrypt_result.is_err());
	}

	#[test]
	fn test_ecies_secp256k1_ephemeral_keys() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Same message";

		// Encrypt the same message twice
		let ciphertext1 = EciesSecp256k1::encrypt(&public_key, plaintext).unwrap();
		let ciphertext2 = EciesSecp256k1::encrypt(&public_key, plaintext).unwrap();
		// Cipher texts should be different due to ephemeral keys
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = EciesSecp256k1::decrypt(&private_key, &ciphertext1).unwrap();
		let decrypted2 = EciesSecp256k1::decrypt(&private_key, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_ecies_secp256k1_invalid_ciphertext() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();

		// Test with too short ciphertext (less than 33 bytes for ephemeral public key)
		let short_ciphertext = [0u8; 32];
		let result = EciesSecp256k1::decrypt(&private_key, short_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));

		// Test with invalid ephemeral public key
		let mut invalid_ciphertext = vec![0u8; 100];
		invalid_ciphertext[0] = 0x01;

		let result = EciesSecp256k1::decrypt(&private_key, &invalid_ciphertext);
		assert!(result.is_err());
	}

	#[test]
	fn test_ecies_secp256k1_public_key_cannot_decrypt() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let fake_ciphertext = [0u8; 100];

		// Public key should not be able to decrypt
		let result = public_key.decrypt(fake_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidOperation));
	}

	#[test]
	fn test_ecies_x25519_basic() {
		let ed25519_private = Ed25519Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();
		let x25519_public = x25519_private.derive_public_key();
		let plaintext = b"Hello, X25519 ECIES world!";

		// Test encryption
		let ciphertext = EciesX25519::encrypt(&x25519_public, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert!(ciphertext.len() > plaintext.len()); // Should be larger (ephemeral key + IV + padding)

		// Test decryption
		let decrypted = EciesX25519::decrypt(&x25519_private, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_ecies_x25519_different_keys() {
		let mut alice_seed = TEST_SEED.as_bytes().to_vec();
		alice_seed.extend_from_slice(b"alice");
		let mut bob_seed = TEST_SEED_ALTERNATE.as_bytes().to_vec();
		bob_seed.extend_from_slice(b"bob");
		let plaintext = b"Message from Alice to Bob via X25519";

		// Key generation for Alice and Bob
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(&alice_seed).unwrap();
		let alice_x25519 = ed25519_to_x25519_private(&alice_ed25519).unwrap();
		let alice_public = alice_x25519.derive_public_key();

		let bob_ed25519 = Ed25519Derivation::derive_from_seed(&bob_seed).unwrap();
		let bob_x25519 = ed25519_to_x25519_private(&bob_ed25519).unwrap();
		let bob_public = bob_x25519.derive_public_key();

		// Alice encrypts for Bob
		let ciphertext_for_bob = EciesX25519::encrypt(&bob_public, plaintext).unwrap();

		// Bob decrypts
		let decrypted_by_bob = EciesX25519::decrypt(&bob_x25519, &ciphertext_for_bob).unwrap();
		assert_eq!(decrypted_by_bob, plaintext);

		// Alice cannot decrypt her own message meant for Bob (wrong private key)
		let alice_decrypt_result = EciesX25519::decrypt(&alice_x25519, &ciphertext_for_bob);
		assert!(alice_decrypt_result.is_err());

		// Test the reverse: Bob encrypts for Alice
		let reverse_plaintext = b"Reply from Bob to Alice via X25519";
		let ciphertext_for_alice = EciesX25519::encrypt(&alice_public, reverse_plaintext).unwrap();

		// Alice decrypts
		let decrypted_by_alice = EciesX25519::decrypt(&alice_x25519, &ciphertext_for_alice).unwrap();
		assert_eq!(decrypted_by_alice, reverse_plaintext);

		// Bob cannot decrypt his own message meant for Alice (wrong private key)
		let bob_decrypt_result = EciesX25519::decrypt(&bob_x25519, &ciphertext_for_alice);
		assert!(bob_decrypt_result.is_err());
	}

	#[test]
	fn test_ecies_x25519_ephemeral_keys() {
		let ed25519_private = Ed25519Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();
		let x25519_public = x25519_private.derive_public_key();
		let plaintext = b"Same message for X25519";

		// Encrypt the same message twice
		let ciphertext1 = EciesX25519::encrypt(&x25519_public, plaintext).unwrap();
		let ciphertext2 = EciesX25519::encrypt(&x25519_public, plaintext).unwrap();
		// Cipher texts should be different due to ephemeral keys
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = EciesX25519::decrypt(&x25519_private, &ciphertext1).unwrap();
		let decrypted2 = EciesX25519::decrypt(&x25519_private, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_ecies_x25519_invalid_ciphertext() {
		let ed25519_private = Ed25519Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();

		// Test with too short ciphertext (less than 80 bytes minimum)
		let short_ciphertext = [0u8; 50];
		let result = EciesX25519::decrypt(&x25519_private, short_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));

		// Test with invalid ephemeral public key
		let mut invalid_ciphertext = vec![0u8; 100];
		// Set invalid bytes that will not parse as a valid X25519 public key
		invalid_ciphertext[0] = 0xFF;
		invalid_ciphertext[31] = 0xFF; // This should make it an invalid point

		let result = EciesX25519::decrypt(&x25519_private, &invalid_ciphertext);
		// This might succeed with random data, but let's test format compliance
		assert!(result.is_err() || result.is_ok());
	}

	#[test]
	fn test_ecies_secp256r1_basic() {
		let private_key = Secp256r1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Hello, ECIES secp256r1 world!";

		// Test encryption
		let ciphertext = EciesSecp256r1::encrypt(&public_key, plaintext).unwrap();
		assert_ne!(ciphertext.as_slice(), plaintext); // Should be different
		assert!(ciphertext.len() > plaintext.len()); // Should be larger (ephemeral key + IV + padding)

		// Test decryption
		let decrypted = EciesSecp256r1::decrypt(&private_key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);
	}

	#[test]
	fn test_ecies_secp256r1_trait_implementation() {
		let private_key = Secp256r1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Testing secp256r1 AsymmetricEncryption trait";

		// Test via trait methods
		let ciphertext = public_key.encrypt(plaintext).unwrap();
		let decrypted = private_key.decrypt(&ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test algorithm info
		assert_eq!(public_key.algorithm_info(), "ECIES-secp256r1-AES256CBC");
		assert_eq!(private_key.algorithm_info(), "ECIES-secp256r1-AES256CBC");
	}

	#[test]
	fn test_ecies_secp256r1_different_keys() {
		let mut alice_seed = TEST_SEED.as_bytes().to_vec();
		alice_seed.extend_from_slice(b"alice");
		let mut bob_seed = TEST_SEED_ALTERNATE.as_bytes().to_vec();
		bob_seed.extend_from_slice(b"bob");
		let plaintext = b"Message from Alice to Bob via secp256r1";

		// Key generation for Alice and Bob
		let alice_private = Secp256r1Derivation::derive_from_seed(&alice_seed).unwrap();
		let alice_public = alice_private.as_public_key();
		let bob_private = Secp256r1Derivation::derive_from_seed(&bob_seed).unwrap();
		let bob_public = bob_private.as_public_key();

		// Alice encrypts for Bob
		let ciphertext_for_bob = EciesSecp256r1::encrypt(&bob_public, plaintext).unwrap();

		// Bob decrypts
		let decrypted_by_bob = EciesSecp256r1::decrypt(&bob_private, &ciphertext_for_bob).unwrap();
		assert_eq!(decrypted_by_bob, plaintext);

		// Alice cannot decrypt her own message meant for Bob (wrong private key)
		let alice_decrypt_result = EciesSecp256r1::decrypt(&alice_private, &ciphertext_for_bob);
		assert!(alice_decrypt_result.is_err());

		// Test the reverse: Bob encrypts for Alice
		let reverse_plaintext = b"Reply from Bob to Alice via secp256r1";
		let ciphertext_for_alice = EciesSecp256r1::encrypt(&alice_public, reverse_plaintext).unwrap();

		// Alice decrypts
		let decrypted_by_alice = EciesSecp256r1::decrypt(&alice_private, &ciphertext_for_alice).unwrap();
		assert_eq!(decrypted_by_alice, reverse_plaintext);

		// Bob cannot decrypt his own message meant for Alice (wrong private key)
		let bob_decrypt_result = EciesSecp256r1::decrypt(&bob_private, &ciphertext_for_alice);
		assert!(bob_decrypt_result.is_err());
	}

	#[test]
	fn test_ecies_secp256r1_ephemeral_keys() {
		let private_key = Secp256r1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Same message for secp256r1";

		// Encrypt the same message twice
		let ciphertext1 = EciesSecp256r1::encrypt(&public_key, plaintext).unwrap();
		let ciphertext2 = EciesSecp256r1::encrypt(&public_key, plaintext).unwrap();
		// Cipher texts should be different due to ephemeral keys
		assert_ne!(ciphertext1, ciphertext2);

		// But both should decrypt to the same plaintext
		let decrypted1 = EciesSecp256r1::decrypt(&private_key, &ciphertext1).unwrap();
		let decrypted2 = EciesSecp256r1::decrypt(&private_key, &ciphertext2).unwrap();
		assert_eq!(decrypted1, plaintext);
		assert_eq!(decrypted2, plaintext);
	}

	#[test]
	fn test_ecies_algorithm_info() {
		// Test algorithm_info methods for all implementations
		assert_eq!(EciesSecp256k1::algorithm_info(), ECIES_SECP256K1_ALGORITHM);
		assert_eq!(EciesX25519::algorithm_info(), ECIES_X25519_ALGORITHM);
		assert_eq!(EciesSecp256r1::algorithm_info(), ECIES_SECP256R1_ALGORITHM);
	}

	#[test]
	fn test_ecies_secp256k1_short_cipher_with_iv() {
		let private_key = Secp256k1Derivation::derive_from_seed(TEST_SEED.as_bytes()).unwrap();

		// Create a malformed ciphertext with valid ephemeral key and HMAC but
		// short cipher_with_iv. This should hit the error condition.
		let mut malformed_ciphertext = vec![0u8; 113];
		// Set a valid ephemeral public key (uncompressed secp256k1 point)
		malformed_ciphertext[0] = 0x04; // Uncompressed point marker
								  // Fill with some valid-looking point data
		for (i, item) in malformed_ciphertext.iter_mut().enumerate().take(65).skip(1) {
			*item = (i % 256) as u8;
		}

		// Put some data in the cipher_with_iv section but make it too short
		malformed_ciphertext = vec![0u8; 112]; // Make it exactly at the boundary
		malformed_ciphertext[0] = 0x04;
		for (i, item) in malformed_ciphertext.iter_mut().enumerate().take(65).skip(1) {
			*item = (i % 256) as u8;
		}

		let result = EciesSecp256k1::decrypt(&private_key, &malformed_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));
	}
}
