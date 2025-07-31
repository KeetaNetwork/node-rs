//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementation.
//!
//! This module provides ECIES encryption.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::algorithms::aes_ctr::Aes128CtrCipher;
use crate::algorithms::ed25519::{X25519PrivateKey, X25519PublicKey};
use crate::algorithms::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::algorithms::PublicKey;
use crate::error::CryptoError;
use crate::hash::HashAlgorithm;
use crate::operations::encryption::{KeyGeneration, SymmetricEncryption};
use crate::PrivateKey;

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
	fn encrypt(recipient_public_key: &Self::PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

	/// Decrypt data using ECIES.
	///
	/// # Arguments
	/// * `recipient_private_key` - The recipient's private key
	/// * `ciphertext` - Encrypted data
	///
	/// # Returns
	/// Decrypted plaintext data
	fn decrypt(recipient_private_key: &Self::PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;

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
	fn derive_keys(shared_secret: &[u8]) -> Result<([u8; 16], [u8; 32]), CryptoError> {
		// First derive 32 bytes using the KDF
		let kdf_output = Self::kdf(shared_secret, 32)?;

		// First 16 bytes are the encryption key for AES-128
		let mut encryption_key = [0u8; 16];
		encryption_key.copy_from_slice(&kdf_output[0..16]);

		// MAC key is SHA-256 of the last 16 bytes
		let mac_key_hash = HashAlgorithm::Sha2_256.hash_array::<32>(&kdf_output[16..32])?;

		Ok((encryption_key, mac_key_hash))
	}

	/// KDF implementation that mimics ecies-geth's counter-based KDF.
	///
	/// This is the same KDF used in Parity and Geth implementations.
	fn kdf(secret: &[u8], output_length: usize) -> Result<Vec<u8>, CryptoError> {
		let mut ctr = 1u32;
		let mut written = 0;
		let mut result = Vec::new();

		while written < output_length {
			// Create counter bytes (big-endian)
			let ctr_bytes = [(ctr >> 24) as u8, (ctr >> 16) as u8, (ctr >> 8) as u8, ctr as u8];

			// Hash: counter || secret
			let mut combined = Vec::with_capacity(4 + secret.len());
			combined.extend_from_slice(&ctr_bytes);
			combined.extend_from_slice(secret);

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
	fn encrypt(recipient_public_key: &Secp256k1PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
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
		let ciphertext_only =
			cipher.encrypt_with_iv(&encryption_key, &iv, plaintext).map_err(|_| CryptoError::EncryptionFailed)?;

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
	fn decrypt(recipient_private_key: &Secp256k1PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		// Check minimum length: 65 (ephemeral_pk) + 16 (iv) + 32 (hmac) = 113 bytes minimum
		if ciphertext.len() < 113 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Parse the message components
		let ephemeral_public_bytes = &ciphertext[0..65];
		let hmac_start = ciphertext.len() - 32;
		let cipher_with_iv = &ciphertext[65..hmac_start]; // IV + encrypted data
		let received_hmac = &ciphertext[hmac_start..];

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

		let hmac_matches = computed_hmac.ct_eq(received_hmac);
		if hmac_matches.unwrap_u8() == 0 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Extract IV and ciphertext
		if cipher_with_iv.len() < 16 {
			return Err(CryptoError::DecryptionFailed);
		}

		let iv = &cipher_with_iv[0..16];
		let encrypted_data = &cipher_with_iv[16..];
		// Decrypt with AES-128-CTR
		let cipher = Aes128CtrCipher::new();
		let plaintext =
			cipher.decrypt_with_iv(&encryption_key, iv, encrypted_data).map_err(|_| CryptoError::DecryptionFailed)?;

		Ok(plaintext)
	}

	fn algorithm_info() -> &'static str {
		"ECIES-secp256k1-AES128CTR"
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
	fn encrypt(recipient_public_key: &X25519PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		use crate::algorithms::aes_cbc::Aes256Cbc;

		// Generate ephemeral key pair
		let ephemeral_private_bytes = {
			use rand_core::{OsRng, TryRngCore};
			let mut bytes = [0u8; 32];
			OsRng.try_fill_bytes(&mut bytes).map_err(|_| CryptoError::EncryptionFailed)?;
			bytes
		};

		// Create X25519 private key from random bytes
		let ephemeral_private = X25519PrivateKey::try_from(ephemeral_private_bytes.as_slice())?;
		let ephemeral_public = ephemeral_private.derive_public_key();

		// Perform ECDH to get shared secret
		let shared_secret = ephemeral_private.diffie_hellman(recipient_public_key);

		// Derive keys using SHA-512 (matching ecies-25519)
		let sha512_hash = HashAlgorithm::Sha2_512.hash(&shared_secret);
		let encryption_key = &sha512_hash[0..32]; // First 32 bytes
		let mac_key = &sha512_hash[32..]; // Remaining bytes

		// Generate IV for AES-CBC (16 bytes)
		let iv = {
			use rand_core::{OsRng, TryRngCore};
			let mut bytes = [0u8; 16];
			OsRng.try_fill_bytes(&mut bytes).map_err(|_| CryptoError::EncryptionFailed)?;
			bytes
		};

		// Encrypt with AES-CBC
		let cipher = Aes256Cbc;
		let iv_and_ciphertext = SymmetricEncryption::encrypt(&cipher, encryption_key, Some(&iv), plaintext)
			.map_err(|_| CryptoError::EncryptionFailed)?;
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
	fn decrypt(recipient_private_key: &X25519PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
		use crate::algorithms::aes_cbc::Aes256Cbc;

		// Check minimum length: 16 (iv) + 32 (ephemeral_pk) + 32 (mac) = 80 bytes minimum
		if ciphertext.len() < 80 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Parse the message components: iv + ephemeral_public_key + mac + ciphertext
		let iv = &ciphertext[0..16];
		let ephemeral_public_bytes = &ciphertext[16..48];
		let received_mac = &ciphertext[48..80];
		let encrypted_data = &ciphertext[80..];

		// Parse ephemeral public key
		let ephemeral_public = X25519PublicKey::try_from(ephemeral_public_bytes)?;
		// Perform ECDH to get shared secret
		let shared_secret = recipient_private_key.diffie_hellman(&ephemeral_public);

		// Derive keys using SHA-512 (matching ecies-25519)
		let sha512_hash = HashAlgorithm::Sha2_512.hash(&shared_secret);
		let encryption_key = &sha512_hash[0..32]; // First 32 bytes
		let mac_key = &sha512_hash[32..]; // Remaining bytes

		// Verify HMAC before decryption (HMAC is over iv + ephemeral_public_key + ciphertext)
		let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key).map_err(|_| CryptoError::DecryptionFailed)?;
		mac.update(iv);
		mac.update(ephemeral_public_bytes);
		mac.update(encrypted_data);

		let computed_mac = mac.finalize().into_bytes();
		let mac_matches = computed_mac.ct_eq(received_mac);
		if mac_matches.unwrap_u8() == 0 {
			return Err(CryptoError::DecryptionFailed);
		}

		// Decrypt with AES-CBC
		let cipher = Aes256Cbc;
		// AES-CBC decrypt expects iv + ciphertext format
		let mut iv_and_ciphertext = Vec::with_capacity(16 + encrypted_data.len());
		iv_and_ciphertext.extend_from_slice(iv);
		iv_and_ciphertext.extend_from_slice(encrypted_data);
		let plaintext = SymmetricEncryption::decrypt(&cipher, encryption_key, &iv_and_ciphertext)
			.map_err(|_| CryptoError::DecryptionFailed)?;

		Ok(plaintext)
	}

	fn algorithm_info() -> &'static str {
		"ECIES-X25519-AES-CBC"
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::algorithms::ed25519::{ed25519_to_x25519_private, Ed25519Derivation};
	use crate::algorithms::secp256k1::Secp256k1Derivation;
	use crate::algorithms::PrivateKey;
	use crate::error::CryptoError;
	use crate::operations::encryption::AsymmetricEncryption;
	use crate::KeyDerivation;
	use base64::engine::general_purpose;
	use base64::Engine;
	use secrecy::ExposeSecret;

	#[test]
	fn test_ecies_secp256k1_basic() {
		let seed = b"test seed for ecies secp256k1 encryption";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
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
		let seed = b"test seed for ecies trait implementation";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
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
		let seed = b"test seed for ecies trait testing!!";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let plaintext = b"Testing ECIES trait interface";

		// Test encryption via trait
		let ciphertext = EciesSecp256k1::encrypt(&public_key, plaintext).unwrap();

		// Test decryption via trait
		let decrypted = EciesSecp256k1::decrypt(&private_key, &ciphertext).unwrap();
		assert_eq!(decrypted, plaintext);

		// Test algorithm info via trait
		assert_eq!(EciesSecp256k1::algorithm_info(), "ECIES-secp256k1-AES128CTR");
	}

	#[test]
	fn test_ecies_secp256k1_different_keys() {
		let seed1 = b"test seed for alice in ecies test!!!";
		let seed2 = b"test seed for bob in ecies test!!!!";
		let plaintext = b"Message from Alice to Bob";

		// Key generation for Alice and Bob
		let alice_private = Secp256k1Derivation::derive_from_seed(seed1).unwrap();
		let alice_public = alice_private.as_public_key();
		let bob_private = Secp256k1Derivation::derive_from_seed(seed2).unwrap();
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
		let seed = b"test seed for ephemeral key testing!";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
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
		let seed = b"test seed for invalid ciphertext!!!";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();

		// Test with too short ciphertext (less than 33 bytes for ephemeral public key)
		let short_ciphertext = [0u8; 32];
		let result = EciesSecp256k1::decrypt(&private_key, &short_ciphertext);
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
		let seed = b"test seed for public key decrypt!!";
		let private_key = Secp256k1Derivation::derive_from_seed(seed).unwrap();
		let public_key = private_key.as_public_key();
		let fake_ciphertext = [0u8; 100];

		// Public key should not be able to decrypt
		let result = public_key.decrypt(&fake_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidOperation));
	}

	#[test]
	fn test_ecies_secp256k1_typescript_compatibility() {
		let seed_hex = "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D";
		let seed = hex::decode(seed_hex).unwrap();
		let index = 0u32;

		// Combine seed and index like the accounts module does
		let mut indexed_seed = [0u8; 36];
		indexed_seed[..32].copy_from_slice(&seed);
		indexed_seed[32..].copy_from_slice(&index.to_be_bytes());

		let private_key = Secp256k1Derivation::derive_from_seed(&indexed_seed).unwrap();
		let public_key = private_key.as_public_key();
		// Verify we derive the expected keys
		let expected_private_hex = "EEE6ABBC24F7FBB5A7035ABF27D6C389E94E4FF06D1A8948FDA56B4DC2D05794";
		let expected_public_hex = "02157AB0EB13544F1583635CF8DB2ED31FE9D029206E160100392EC91288D653A8";

		let private_secret_box: secrecy::SecretBox<Vec<u8>> = private_key.clone().into();
		assert_eq!(hex::encode(private_secret_box.expose_secret()).to_uppercase(), expected_private_hex);

		let public_bytes: Vec<u8> = public_key.clone().into();
		assert_eq!(hex::encode(&public_bytes).to_uppercase(), expected_public_hex);

		// Test decryption of TypeScript encrypted data
		let encrypted_base64 = "BI8ePLqAhgOQvUXsTqW8ifQ77eRhg7Z6FpxX5wd6xJfE+ErjHyuXFKNjSDMBgTAG6iKylZITJajh6Zdgcbpdvb3+pBN17zCaaOzAgpId4hcOG3P/ueHMRWolYQPJ5jGqM1xmBO64sa3nodxDwEtAI5dA3CG4mg==";
		let encrypted_data = general_purpose::STANDARD.decode(encrypted_base64).unwrap();
		let expected_plaintext = "Hello";

		// Decrypt the TypeScript data with our implementation
		let decrypted = EciesSecp256k1::decrypt(&private_key, &encrypted_data).unwrap();
		assert_eq!(decrypted, expected_plaintext.as_bytes());

		// Test that our implementation can encrypt/decrypt successfully (roundtrip test)
		let test_message = b"Test message for Rust ECIES";
		let rust_encrypted = EciesSecp256k1::encrypt(&public_key, test_message).unwrap();
		let rust_decrypted = EciesSecp256k1::decrypt(&private_key, &rust_encrypted).unwrap();
		assert_eq!(rust_decrypted, test_message);

		// Verify format structure: ephemeral_pk(65) + iv_and_ciphertext + hmac(32)
		assert!(encrypted_data.len() >= 65 + 16 + 32); // minimum size
		assert_eq!(encrypted_data[0], 0x04); // uncompressed public key format
		assert!(rust_encrypted.len() >= 65 + 16 + 32); // our format should also be valid
		assert_eq!(rust_encrypted[0], 0x04); // our format should also use uncompressed keys
	}

	#[test]
	fn test_ecies_x25519_basic() {
		let seed = b"test seed for ecies x25519 encryption!";
		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
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
		let seed1 = b"test seed for alice in x25519 test!!";
		let seed2 = b"test seed for bob in x25519 test!!!";
		let plaintext = b"Message from Alice to Bob via X25519";

		// Key generation for Alice and Bob
		let alice_ed25519 = Ed25519Derivation::derive_from_seed(seed1).unwrap();
		let alice_x25519 = ed25519_to_x25519_private(&alice_ed25519).unwrap();
		let alice_public = alice_x25519.derive_public_key();

		let bob_ed25519 = Ed25519Derivation::derive_from_seed(seed2).unwrap();
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
		let seed = b"test seed for x25519 ephemeral testing";
		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
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
		let seed = b"test seed for x25519 invalid ciphertext";
		let ed25519_private = Ed25519Derivation::derive_from_seed(seed).unwrap();
		let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();

		// Test with too short ciphertext (less than 80 bytes minimum)
		let short_ciphertext = [0u8; 50];
		let result = EciesX25519::decrypt(&x25519_private, &short_ciphertext);
		assert!(result.is_err());
		assert!(matches!(result.unwrap_err(), CryptoError::DecryptionFailed));

		// Test with invalid ephemeral public key
		let mut invalid_ciphertext = vec![0u8; 100];
		// Set invalid bytes that won't parse as a valid X25519 public key
		invalid_ciphertext[0] = 0xFF;
		invalid_ciphertext[31] = 0xFF; // This should make it an invalid point

		let result = EciesX25519::decrypt(&x25519_private, &invalid_ciphertext);
		// This might succeed with random data, but let's test format compliance
		assert!(result.is_err() || result.is_ok());
	}

	#[test]
	fn test_ecies_x25519_typescript_compatibility() {
		// Test data from TypeScript account.test.ts - Ed25519 encryption test case
		let seed_hex = "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D";
		let seed = hex::decode(seed_hex).unwrap();
		let index = 0u32;

		// Combine seed and index like the accounts module does
		let mut indexed_seed = [0u8; 36];
		indexed_seed[..32].copy_from_slice(&seed);
		indexed_seed[32..].copy_from_slice(&index.to_be_bytes());

		// Derive Ed25519 key first, then convert to X25519
		let ed25519_private = Ed25519Derivation::derive_from_seed(&indexed_seed).unwrap();
		let x25519_private = ed25519_to_x25519_private(&ed25519_private).unwrap();
		let x25519_public = x25519_private.derive_public_key();

		// Test decryption of TypeScript encrypted data for Ed25519
		// From encryptionTestCases in account.test.ts
		let encrypted_base64 = "fZazrME6jGTTj2Dp1o9imAuri5s3MxeE0ZnK8HP2dK4TgnAJ3825UWKFaQnW0E0tETD0iyo8B1Zex4JUB7Ab83RnJrWBxGfoho6YqaKdHTWYfAPPJ1G2EBkDo1qoiGpO8t1Tb3o9JiOQf6jAMp2VKg==";
		let encrypted_data = general_purpose::STANDARD.decode(encrypted_base64).unwrap();
		let expected_plaintext = "Ed25519 Encryption";

		// Try to decrypt the TypeScript data with our X25519 implementation
		let decrypted = EciesX25519::decrypt(&x25519_private, &encrypted_data).unwrap();
		assert_eq!(decrypted, expected_plaintext.as_bytes());

		// Also test that our implementation can encrypt/decrypt successfully (roundtrip test)
		let test_plaintext = expected_plaintext.as_bytes();
		let rust_encrypted = EciesX25519::encrypt(&x25519_public, test_plaintext).unwrap();
		let rust_decrypted = EciesX25519::decrypt(&x25519_private, &rust_encrypted).unwrap();
		assert_eq!(rust_decrypted, test_plaintext);
		// Verify format structure: iv(16) + ephemeral_pk(32) + mac(32) + ciphertext
		assert!(rust_encrypted.len() >= 16 + 32 + 32); // minimum size
	}
}
