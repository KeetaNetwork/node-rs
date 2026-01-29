//! Test utilities for cryptographic algorithms.
//!
//! This module provides macros to generate tests for various cryptographic
//! traits and operations.

use crate::algorithms::ed25519::{ed25519_to_x25519_private, Ed25519Derivation, X25519PrivateKey, X25519PublicKey};
use crate::algorithms::secp256k1::{Secp256k1Derivation, Secp256k1PrivateKey, Secp256k1PublicKey};
use crate::algorithms::secp256r1::{Secp256r1Derivation, Secp256r1PrivateKey, Secp256r1PublicKey};
use crate::algorithms::{KeyDerivation, PrivateKey};
use crate::IntoSecret;

/// Constant test seed for deterministic and reproducible test results
pub const TEST_SEED: &[u8] = b"able able able able able able able able able able able able";
pub const TEST_SEED_ALTERNATE: &[u8] = b"art art art art art art art art art art art art";

/// Generic helper to create any key pair from seed
pub fn create_keypair<T, D>(seed: &str, suffix: Option<&str>) -> Result<(T, T::PublicKey), crate::error::CryptoError>
where
	T: PrivateKey,
	D: KeyDerivation<PrivateKey = T>,
{
	let mut seed_bytes = seed.as_bytes().to_vec();
	if let Some(suffix) = suffix {
		seed_bytes.extend_from_slice(suffix.as_bytes());
	}

	let private_key = D::derive_from_seed(seed_bytes.into_secret())?;
	let public_key = private_key.as_public_key();
	Ok((private_key, public_key))
}

/// Helper function to create a secp256k1 key pair
pub fn create_secp256k1_keypair(
	seed: &str,
	suffix: Option<&str>,
) -> Result<(Secp256k1PrivateKey, Secp256k1PublicKey), crate::error::CryptoError> {
	create_keypair::<Secp256k1PrivateKey, Secp256k1Derivation>(seed, suffix)
}

/// Helper function to create a secp256r1 key pair
pub fn create_secp256r1_keypair(
	seed: &str,
	suffix: Option<&str>,
) -> Result<(Secp256r1PrivateKey, Secp256r1PublicKey), crate::error::CryptoError> {
	create_keypair::<Secp256r1PrivateKey, Secp256r1Derivation>(seed, suffix)
}

/// Helper to create X25519 key pair from Ed25519 seed
pub fn create_x25519_keypair(
	seed: &str,
	suffix: Option<&str>,
) -> Result<(X25519PrivateKey, X25519PublicKey), crate::error::CryptoError> {
	let mut seed_bytes = seed.as_bytes().to_vec();
	if let Some(suffix) = suffix {
		seed_bytes.extend_from_slice(suffix.as_bytes());
	}

	let ed25519_private = Ed25519Derivation::derive_from_seed(seed_bytes.into_secret())?;

	let x25519_private = ed25519_to_x25519_private(&ed25519_private)?;
	let x25519_public = x25519_private.derive_public_key();
	Ok((x25519_private, x25519_public))
}

/// Macro to generate tests for KeyDerivation trait implementations.
macro_rules! test_key_derivation {
	(
		$derivation_type:ty,
		$private_key_type:ty,
		$public_key_type:ty,
		$expected_key_len:expr,
		$expected_hex_len:expr,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_key_derivation() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();

			// Test serialization roundtrip
			let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
			let _recovered_private = <$private_key_type>::try_from(private_bytes.expose_secret().as_slice())?;
			assert_eq!(
				SecretBox::<Vec<u8>>::from(&private_key).expose_secret(),
				SecretBox::<Vec<u8>>::from(&_recovered_private).expose_secret()
			);
			let public_bytes: Vec<u8> = (&public_key).into();
			let recovered_public = <$public_key_type>::try_from(public_bytes.as_slice())?;
			assert_eq!(Vec::<u8>::from(&public_key), Vec::<u8>::from(&recovered_public));

			// Test public key formatting
			let hex_formatted = hex::encode(Vec::<u8>::from(&public_key));
			assert_eq!(hex_formatted.len(), $expected_hex_len);

			// Test public key length
			let public_key_bytes = Vec::<u8>::from(&public_key);
			assert_eq!(public_key_bytes.len(), $expected_key_len);
			Ok(())
		}

		#[test]
		fn test_deterministic() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED_ALTERNATE;
			let key1 = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let key2 = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			assert_eq!(
				SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
				SecretBox::<Vec<u8>>::from(&key2).expose_secret()
			);

			let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());
			assert_eq!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
			Ok(())
		}

		#[test]
		fn test_different_seeds() -> Result<(), Box<dyn core::error::Error>> {
			// Create two different seeds by modifying the constant
			let mut seed1 = crate::test_utils::TEST_SEED.to_vec();
			let mut seed2 = crate::test_utils::TEST_SEED.to_vec();
			seed1.extend_from_slice(b"_seed1");
			seed2.extend_from_slice(b"_seed2");

			let key1 = <$derivation_type>::derive_from_seed(seed1.into_secret())?;
			let key2 = <$derivation_type>::derive_from_seed(seed2.into_secret())?;
			// Different seeds should produce different keys
			assert_ne!(
				SecretBox::<Vec<u8>>::from(&key1).expose_secret(),
				SecretBox::<Vec<u8>>::from(&key2).expose_secret()
			);

			let (pub1, pub2) = (key1.as_public_key(), key2.as_public_key());
			assert_ne!(Vec::<u8>::from(&pub1), Vec::<u8>::from(&pub2));
			Ok(())
		}

		#[test]
		fn test_serialization_roundtrip() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();

			// Test private key serialization
			let private_bytes: SecretBox<Vec<u8>> = (&private_key).into();
			let _recovered_private = <$private_key_type>::try_from(private_bytes.expose_secret().as_slice())?;
			let public_bytes: Vec<u8> = (&public_key).into();
			let recovered_public = <$public_key_type>::try_from(public_bytes.as_slice())?;

			// Verify keys match
			let original_pub_bytes = Vec::<u8>::from(&public_key);
			let recovered_pub_bytes = Vec::<u8>::from(&recovered_public);
			assert_eq!(original_pub_bytes, recovered_pub_bytes);
			Ok(())
		}
	};
}

/// Macro to generate utility tests for key derivation and debug formatting.
macro_rules! test_crypto_utils {
	(
		$derivation_type:ty,
		$private_key_type:ty,
		$expected_key_size:expr,
		$algo_name:expr,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_key_derivation_utility_methods() {
			// Test is_valid_key_material with valid key
			let valid_key = [0x01; $expected_key_size]; // Valid key
			assert!(<$derivation_type>::is_valid_key_material(valid_key));

			// Test is_valid_key_material with invalid key (wrong length)
			let invalid_key = [0x01; 16]; // Invalid length
			assert!(!<$derivation_type>::is_valid_key_material(invalid_key));

			// Test is_valid_key_material with invalid key (all zeros)
			// Note: Ed25519 allows zero keys, but ECDSA curves don't
			let zero_key = [0x00; $expected_key_size];
			if $algo_name != "ed25519" {
				assert!(!<$derivation_type>::is_valid_key_material(zero_key));
			}

			// Test key_size
			assert_eq!(<$derivation_type>::key_size(), $expected_key_size);
		}

		#[test]
		fn test_debug_formatting() -> Result<(), Box<dyn core::error::Error>> {
			let mut seed = crate::test_utils::TEST_SEED.to_vec();
			seed.extend_from_slice(concat!("_", $seed_suffix, "_debug").as_bytes());

			let private_key = <$derivation_type>::derive_from_seed(seed.into_secret())?;

			// Test that Debug format hides the private key
			let debug_string = format!("{private_key:?}");
			assert!(debug_string.contains(concat!(stringify!($private_key_type))));
			assert!(debug_string.contains("[REDACTED]"));
			// Make sure no actual key bytes are shown
			assert!(!debug_string.contains("SecretKey"));
			Ok(())
		}
	};
}

/// Macro to generate tests for signing and verification operations.
#[cfg(feature = "signature")]
macro_rules! test_signatures {
	(
		$derivation_type:ty,
		$seed_suffix:expr
	) => {
		const TEST_MESSAGE: &[u8] = b"test message for signing";

		#[test]
		fn test_signing_operations() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();

			// Test signing
			let signature = private_key.try_sign(TEST_MESSAGE)?;
			// Test verification
			assert!(public_key.verify(TEST_MESSAGE, &signature).is_ok());

			// Test verification fails with wrong message
			let wrong_message = b"wrong message";
			assert!(public_key.verify(wrong_message, &signature).is_err());
			Ok(())
		}

		#[test]
		fn test_signature_deterministic() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;

			// Sign the same message twice
			let signature1 = private_key.try_sign(TEST_MESSAGE)?;
			let signature2 = private_key.try_sign(TEST_MESSAGE)?;
			// Signatures should be identical (deterministic)
			assert_eq!(signature1.to_bytes(), signature2.to_bytes());
			Ok(())
		}

		#[test]
		fn test_signature_verification_failures() -> Result<(), Box<dyn core::error::Error>> {
			// Create different seeds for Alice and Bob
			let mut alice_seed = crate::test_utils::TEST_SEED.to_vec();
			let mut bob_seed = crate::test_utils::TEST_SEED.to_vec();
			alice_seed.extend_from_slice(b"_alice");
			bob_seed.extend_from_slice(b"_bob");

			let alice_private = <$derivation_type>::derive_from_seed(alice_seed.into_secret())?;
			let alice_public = alice_private.as_public_key();
			let bob_private = <$derivation_type>::derive_from_seed(bob_seed.into_secret())?;
			let bob_public = bob_private.as_public_key();

			// Alice signs a message
			let alice_signature = alice_private.try_sign(TEST_MESSAGE)?;
			// Alice's signature should verify with Alice's public key
			assert!(alice_public.verify(TEST_MESSAGE, &alice_signature).is_ok());
			// Alice's signature should NOT verify with Bob's public key
			assert!(bob_public.verify(TEST_MESSAGE, &alice_signature).is_err());

			// Bob signs the same message
			let bob_signature = bob_private.try_sign(TEST_MESSAGE)?;
			// Bob's signature should be different from Alice's
			assert_ne!(alice_signature.to_bytes(), bob_signature.to_bytes());
			// Bob's signature should verify with Bob's public key
			assert!(bob_public.verify(TEST_MESSAGE, &bob_signature).is_ok());
			Ok(())
		}

		#[test]
		fn test_crypto_signer_ext_trait() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;

			assert!(private_key.has_private_key());

			let algorithm = private_key.to_algorithm();
			let expected_algorithm = match stringify!($seed_suffix) {
				"\"ed25519\"" => crate::algorithms::Algorithm::Ed25519,
				"\"secp256k1\"" => crate::algorithms::Algorithm::Secp256k1,
				"\"secp256r1\"" => crate::algorithms::Algorithm::Secp256r1,
				_ => return Err("Unknown algorithm".into()),
			};
			assert_eq!(algorithm, expected_algorithm);

			let verifying_key = private_key.verifying_key();
			assert!(!verifying_key.public_key_bytes().is_empty());

			// Test that verifying key matches the public key
			let expected_public_key = private_key.as_public_key();
			assert_eq!(verifying_key.public_key_bytes(), Vec::<u8>::from(&expected_public_key));
			Ok(())
		}

		#[test]
		fn test_crypto_verifier_ext_trait() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();

			let public_key_bytes = public_key.public_key_bytes();
			let expected_len = match stringify!($seed_suffix) {
				"\"ed25519\"" => 32,   // Ed25519 public keys are 32 bytes
				"\"secp256k1\"" => 33, // secp256k1 compressed public keys are 33 bytes
				"\"secp256r1\"" => 33, // secp256r1 compressed public keys are 33 bytes
				_ => return Err("Unknown algorithm".into()),
			};
			assert_eq!(public_key_bytes.len(), expected_len);
			Ok(())
		}

		#[test]
		fn test_crypto_signer_with_options() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let message = b"test message for signing with options";

			// Test with default options (pre-hash)
			let default_options = crate::operations::signature::SigningOptions::default();
			let signature_default = private_key.sign_with_options(message, default_options)?;

			// Test with raw options (no pre-hash)
			let raw_options = crate::operations::signature::SigningOptions::raw();
			// Use a different 32-byte hash to make it truly different
			let different_hash = [0x42u8; 32]; // Different from hash_default(message)
			let signature_raw = private_key.sign_with_options(different_hash, raw_options)?;

			// Test with cert options (pre-hash, but for_cert flag set)
			let cert_options = crate::operations::signature::SigningOptions::for_cert();
			let signature_cert = private_key.sign_with_options(message, cert_options)?;

			// Signatures should be different when using different message processing
			assert_ne!(signature_default.to_bytes(), signature_raw.to_bytes());

			// For Ed25519, default and cert should be the same since they both pre-hash
			// For ECDSA curves, they should be different due to different hash algorithms
			if stringify!($seed_suffix) == "\"ed25519\"" {
				assert_eq!(signature_default.to_bytes(), signature_cert.to_bytes());
			} else {
				assert_ne!(signature_default.to_bytes(), signature_cert.to_bytes());
			}

			// Verify that the regular signing (which signs raw message) differs from options-based signing (which pre-hashes)
			// For Ed25519: try_sign signs raw message, sign_with_options(default) signs hash of message
			// For ECDSA: try_sign pre-hashes using one method, sign_with_options(default) might use different hash
			let regular_signature = private_key.try_sign(message)?;
			assert_ne!(regular_signature.to_bytes(), signature_default.to_bytes());
			Ok(())
		}

		#[test]
		fn test_crypto_verifier_with_options() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();
			let message = b"test message for verification with options";

			// Test verification with matching options
			let default_options = crate::operations::signature::SigningOptions::default();
			let signature_default = private_key.sign_with_options(message, default_options)?;
			assert!(public_key
				.verify_with_options(message, &signature_default, default_options)
				.is_ok());

			// For raw options, we need to use a pre-computed hash (32 bytes)
			let raw_options = crate::operations::signature::SigningOptions::raw();
			let pre_computed_hash = crate::hash::hash_default(message);
			let signature_raw = private_key.sign_with_options(pre_computed_hash, raw_options)?;
			assert!(public_key
				.verify_with_options(pre_computed_hash, &signature_raw, raw_options)
				.is_ok());

			let cert_options = crate::operations::signature::SigningOptions::for_cert();
			let signature_cert = private_key.sign_with_options(message, cert_options)?;
			assert!(public_key
				.verify_with_options(message, &signature_cert, cert_options)
				.is_ok());

			// Test verification failure with mismatched options
			assert!(public_key
				.verify_with_options(pre_computed_hash, &signature_raw, default_options)
				.is_err());
			assert!(public_key
				.verify_with_options(message, &signature_default, raw_options)
				.is_err());

			// Test verification failure with wrong message
			let wrong_message = b"wrong message";
			assert!(public_key
				.verify_with_options(wrong_message, &signature_default, default_options)
				.is_err());
			Ok(())
		}
	};
}

/// Macro to generate tests for KeyExchange trait implementations.
#[cfg(feature = "encryption")]
macro_rules! test_key_exchange {
	(
		$derivation_type:ty,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_ecdh_operations() -> Result<(), Box<dyn core::error::Error>> {
			// Create two different seeds for Alice and Bob
			let mut alice_seed = crate::test_utils::TEST_SEED.to_vec();
			let mut bob_seed = crate::test_utils::TEST_SEED.to_vec();
			alice_seed.extend_from_slice(b"_alice");
			bob_seed.extend_from_slice(b"_bob");

			let alice_private = <$derivation_type>::derive_from_seed(alice_seed.into_secret())?;
			let alice_public = alice_private.as_public_key();
			let bob_private = <$derivation_type>::derive_from_seed(bob_seed.into_secret())?;
			let bob_public = bob_private.as_public_key();

			// Perform ECDH
			let alice_shared = alice_private.ecdh(&bob_public)?;
			let bob_shared = bob_private.ecdh(&alice_public)?;
			// Shared secrets should match
			assert_eq!(alice_shared, bob_shared);
			assert!(!alice_shared.is_empty());
			Ok(())
		}

		#[test]
		fn test_ecdh_consistency() -> Result<(), Box<dyn core::error::Error>> {
			// Create two different seeds
			let mut seed1 = crate::test_utils::TEST_SEED.to_vec();
			let mut seed2 = crate::test_utils::TEST_SEED.to_vec();
			seed1.extend_from_slice(b"_test1");
			seed2.extend_from_slice(b"_test2");

			let key1 = <$derivation_type>::derive_from_seed(seed1.into_secret())?;
			let key2 = <$derivation_type>::derive_from_seed(seed2.into_secret())?;
			let pub1 = key1.as_public_key();
			let pub2 = key2.as_public_key();

			// Test that ECDH is commutative: key1.ecdh(pub2) == key2.ecdh(pub1)
			let shared1 = key1.ecdh(&pub2)?;
			let shared2 = key2.ecdh(&pub1)?;
			assert_eq!(shared1, shared2);

			// Test that self-ECDH works
			let self_shared = key1.ecdh(&pub1)?;
			assert!(!self_shared.is_empty());
			Ok(())
		}
	};
}

/// Macro to generate ECDH key exchange tests.
#[cfg(feature = "encryption")]
macro_rules! test_ecdh {
	(
		$derivation_type:ty,
		$private_key_type:ty,
		$public_key_type:ty,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_ecdh_key_exchange_trait() -> Result<(), Box<dyn core::error::Error>> {
			// Create seeds for key exchange testing
			let mut seed1 = crate::test_utils::TEST_SEED.to_vec();
			let mut seed2 = crate::test_utils::TEST_SEED_ALTERNATE.to_vec();
			seed1.extend_from_slice(concat!("_", $seed_suffix, "_1").as_bytes());
			seed2.extend_from_slice(concat!("_", $seed_suffix, "_2").as_bytes());

			let private_key1 = <$derivation_type>::derive_from_seed(seed1.into_secret())?;
			let private_key2 = <$derivation_type>::derive_from_seed(seed2.into_secret())?;

			let public_key1 = private_key1.as_public_key();
			let public_key2 = private_key2.as_public_key();

			// Test ECDH key exchange with public key objects
			let shared_secret1 = private_key1.ecdh(&public_key2)?;
			let shared_secret2 = private_key2.ecdh(&public_key1)?;
			// Both parties should compute the same shared secret
			assert_eq!(shared_secret1, shared_secret2);
			assert!(!shared_secret1.is_empty());

			// Test key_exchange with public key bytes
			let public_key2_bytes: Vec<u8> = (&public_key2).into();
			let shared_secret1_bytes = private_key1.key_exchange(&public_key2_bytes)?;
			assert_eq!(shared_secret1, shared_secret1_bytes);

			let public_key1_bytes: Vec<u8> = (&public_key1).into();
			let shared_secret2_bytes = private_key2.key_exchange(&public_key1_bytes)?;
			assert_eq!(shared_secret2, shared_secret2_bytes);

			// Test that different key pairs produce different shared secrets
			let mut seed3 = crate::test_utils::TEST_SEED.to_vec();
			seed3.extend_from_slice(concat!("_", $seed_suffix, "_3").as_bytes());
			let private_key3 = <$derivation_type>::derive_from_seed(seed3.into_secret())?;
			let public_key3 = private_key3.as_public_key();

			let shared_secret3 = private_key1.ecdh(&public_key3)?;
			assert_ne!(shared_secret1, shared_secret3);

			// Test error handling with invalid public key bytes
			let invalid_public_key = vec![0u8; 32]; // Wrong length
			let result = private_key1.key_exchange(&invalid_public_key);
			assert!(result.is_err());

			// Test derive_aead_key - expected to return EncryptionNotSupported for these curves
			let aead_result = private_key1.derive_aead_key::<aes_gcm::Aes256Gcm>(&shared_secret1);
			assert!(aead_result.is_err());
			// Test that it specifically returns EncryptionNotSupported
			assert!(matches!(aead_result, Err(CryptoError::EncryptionNotSupported)));
			Ok(())
		}
	};
}

/// Macro to generate tests for DER/ASN.1 operations.
#[cfg(any(feature = "der", feature = "rasn"))]
macro_rules! test_der {
	(
		$derivation_type:ty,
		$expected_oid:expr,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_oid_conversion() -> Result<(), Box<dyn core::error::Error>> {
			let mut seed = crate::test_utils::TEST_SEED.to_vec();
			seed.extend_from_slice(concat!("_", $seed_suffix, "_oid").as_bytes());

			let private_key = <$derivation_type>::derive_from_seed(seed.into_secret())?;
			let public_key = private_key.as_public_key();

			// Test conversion to ObjectIdentifier
			let oid: keetanetwork_asn1::ObjectIdentifier = public_key.into();
			assert_eq!(oid.to_string(), $expected_oid);

			let oid: keetanetwork_asn1::ObjectIdentifier = private_key.into();
			assert_eq!(oid.to_string(), $expected_oid);
			Ok(())
		}
	};
}

/// Macro to generate tests for AsymmetricEncryption trait implementations.
#[cfg(feature = "encryption")]
macro_rules! test_asymmetric_encryption {
	(
		$derivation_type:ty,
		$seed_suffix:expr
	) => {
		#[test]
		fn test_asymmetric_encryption_trait() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let public_key = private_key.as_public_key();
			let plaintext = b"test message for asymmetric encryption trait";

			// Test encryption via private key (should delegate to public key)
			let ciphertext_from_private = private_key.encrypt(plaintext)?;
			assert!(!ciphertext_from_private.is_empty());
			assert_ne!(ciphertext_from_private.as_slice(), plaintext);

			// Test encryption via public key directly
			let ciphertext_from_public = public_key.encrypt(plaintext)?;
			assert!(!ciphertext_from_public.is_empty());
			assert_ne!(ciphertext_from_public.as_slice(), plaintext);

			// Both should be different due to ephemeral keys in ECIES
			assert_ne!(ciphertext_from_private, ciphertext_from_public);

			// Test decryption with private key
			let decrypted_from_private = private_key.decrypt(&ciphertext_from_private)?;
			assert_eq!(decrypted_from_private, plaintext);

			let decrypted_from_public = private_key.decrypt(&ciphertext_from_public)?;
			assert_eq!(decrypted_from_public, plaintext);

			// Test that public key cannot decrypt
			let decrypt_result1 = public_key.decrypt(&ciphertext_from_private);
			assert!(matches!(decrypt_result1, Err(CryptoError::InvalidOperation)));
			Ok(())
		}

		#[test]
		fn test_asymmetric_encryption_round_trip() -> Result<(), Box<dyn core::error::Error>> {
			let seed = crate::test_utils::TEST_SEED;
			let private_key = <$derivation_type>::derive_from_seed(seed.to_vec().into_secret())?;
			let plaintext = b"round trip test data with various characters: 123!@#$%^&*()";

			// Test full round-trip using private key encrypt/decrypt
			let encrypted = private_key.encrypt(plaintext)?;
			assert_ne!(encrypted.as_slice(), plaintext);

			let decrypted = private_key.decrypt(&encrypted)?;
			assert_eq!(decrypted, plaintext);
			Ok(())
		}

		#[test]
		fn test_asymmetric_encryption_different_keys() -> Result<(), Box<dyn core::error::Error>> {
			// Create different key pairs
			let mut seed1 = crate::test_utils::TEST_SEED.to_vec();
			let mut seed2 = crate::test_utils::TEST_SEED_ALTERNATE.to_vec();
			seed1.extend_from_slice(concat!("_", $seed_suffix, "_enc1").as_bytes());
			seed2.extend_from_slice(concat!("_", $seed_suffix, "_enc2").as_bytes());

			let private_key1 = <$derivation_type>::derive_from_seed(seed1.into_secret())?;
			let private_key2 = <$derivation_type>::derive_from_seed(seed2.into_secret())?;
			let public_key2 = private_key2.as_public_key();

			let plaintext = b"test cross-key encryption";

			// Encrypt with public key 2
			let ciphertext = public_key2.encrypt(plaintext)?;

			// Private key 2 should be able to decrypt
			let decrypted = private_key2.decrypt(&ciphertext)?;
			assert_eq!(decrypted, plaintext);

			// Private key 1 should NOT be able to decrypt
			let decrypt_result = private_key1.decrypt(&ciphertext);
			assert!(decrypt_result.is_err());
			Ok(())
		}
	};
}

/// Macro to generate tests for ECIES implementations
#[cfg(feature = "encryption")]
macro_rules! test_ecies {
	(
		$mod_name:ident,
		$ecies_type:ty,
		$create_keypair_fn:ident
	) => {
		mod $mod_name {
			use super::*;
			use crate::error::CryptoError;
			use crate::operations::encryption::AsymmetricEncryption;

			#[test]
			fn basic() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (private_key, public_key) = $create_keypair_fn(seed, None)?;
				let plaintext = b"Hello, ECIES world!";

				// Test encryption
				let ciphertext = <$ecies_type>::encrypt(&public_key, plaintext)?;
				assert_ne!(ciphertext.as_slice(), plaintext);
				assert!(ciphertext.len() > plaintext.len());

				// Test decryption
				let decrypted = <$ecies_type>::decrypt(&private_key, &ciphertext)?;
				assert_eq!(decrypted, plaintext);
				Ok(())
			}

			#[test]
			fn trait_implementation() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (private_key, public_key) = $create_keypair_fn(seed, None)?;
				let plaintext = b"Testing AsymmetricEncryption trait";

				// Test via trait methods
				let ciphertext: Vec<u8> = public_key.encrypt(plaintext)?;
				let decrypted: Vec<u8> = private_key.decrypt(&ciphertext)?;
				assert_eq!(decrypted, plaintext);
				Ok(())
			}

			#[test]
			fn different_keys() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (alice_private, alice_public) = $create_keypair_fn(seed, Some("alice"))?;
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED_ALTERNATE)?;
				let (bob_private, bob_public) = $create_keypair_fn(seed, Some("bob"))?;
				let plaintext = b"Message from Alice to Bob";

				// Alice encrypts for Bob
				let ciphertext_for_bob = <$ecies_type>::encrypt(&bob_public, plaintext)?;

				// Bob decrypts
				let decrypted_by_bob = <$ecies_type>::decrypt(&bob_private, &ciphertext_for_bob)?;
				assert_eq!(decrypted_by_bob, plaintext);

				// Alice cannot decrypt her own message meant for Bob
				let alice_decrypt_result = <$ecies_type>::decrypt(&alice_private, &ciphertext_for_bob);
				assert!(alice_decrypt_result.is_err());

				// Test the reverse: Bob encrypts for Alice
				let reverse_plaintext = b"Reply from Bob to Alice";
				let ciphertext_for_alice = <$ecies_type>::encrypt(&alice_public, reverse_plaintext)?;

				// Alice decrypts
				let decrypted_by_alice = <$ecies_type>::decrypt(&alice_private, &ciphertext_for_alice)?;
				assert_eq!(decrypted_by_alice, reverse_plaintext);

				// Bob cannot decrypt his own message meant for Alice
				let bob_decrypt_result = <$ecies_type>::decrypt(&bob_private, &ciphertext_for_alice);
				assert!(bob_decrypt_result.is_err());
				Ok(())
			}

			#[test]
			fn ephemeral_keys() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (private_key, public_key) = $create_keypair_fn(seed, None)?;
				let plaintext = b"Same message";

				// Encrypt the same message twice
				let ciphertext1 = <$ecies_type>::encrypt(&public_key, plaintext)?;
				let ciphertext2 = <$ecies_type>::encrypt(&public_key, plaintext)?;

				// Cipher texts should be different due to ephemeral keys
				assert_ne!(ciphertext1, ciphertext2);

				// But both should decrypt to the same plaintext
				let decrypted1 = <$ecies_type>::decrypt(&private_key, &ciphertext1)?;
				let decrypted2 = <$ecies_type>::decrypt(&private_key, &ciphertext2)?;
				assert_eq!(decrypted1, plaintext);
				assert_eq!(decrypted2, plaintext);
				Ok(())
			}

			#[test]
			fn invalid_ciphertext() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (private_key, _) = $create_keypair_fn(seed, None)?;

				// Test with too short ciphertext
				let short_ciphertext = [0u8; 50];
				let result = <$ecies_type>::decrypt(&private_key, short_ciphertext);
				assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
				Ok(())
			}

			#[test]
			fn public_key_cannot_decrypt() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (_, public_key) = $create_keypair_fn(seed, None)?;
				let fake_ciphertext = [0u8; 100];

				// Public key should not be able to decrypt
				let result: Result<Vec<u8>, CryptoError> = public_key.decrypt(fake_ciphertext);
				assert!(matches!(result, Err(CryptoError::InvalidOperation)));
				Ok(())
			}

			#[test]
			fn short_cipher_boundary_condition() -> Result<(), Box<dyn core::error::Error>> {
				let seed = core::str::from_utf8(crate::test_utils::TEST_SEED)?;
				let (private_key, _) = $create_keypair_fn(seed, None)?;

				// Create a malformed ciphertext with valid ephemeral key and HMAC but
				// short cipher_with_iv. This should hit the error condition.
				let mut malformed_ciphertext = vec![0u8; 113];
				// Set a valid ephemeral public key (uncompressed point marker)
				malformed_ciphertext[0] = 0x04;
				// Fill with some valid-looking point data
				for (i, item) in malformed_ciphertext.iter_mut().enumerate().take(65).skip(1) {
					*item = (i % 256) as u8;
				}

				// Put some data in the cipher section but make it too short
				malformed_ciphertext = vec![0u8; 112]; // Make it exactly at the boundary
				malformed_ciphertext[0] = 0x04;
				for (i, item) in malformed_ciphertext.iter_mut().enumerate().take(65).skip(1) {
					*item = (i % 256) as u8;
				}

				let result = <$ecies_type>::decrypt(&private_key, &malformed_ciphertext);
				assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
				Ok(())
			}
		}
	};
}

/// Macro to generate tests for AES symmetric encryption implementations.
#[cfg(feature = "encryption")]
macro_rules! test_aes_symmetric {
	(
		$cipher_type:ty,
		$key_size:expr,
		$cipher_name:expr
	) => {
		#[test]
		fn test_basic_encrypt_decrypt() -> Result<(), Box<dyn core::error::Error>> {
			let cipher = <$cipher_type>::new();
			let key = vec![0x42u8; $key_size];
			let plaintext = b"Hello, AES encryption world!";

			// Test encryption
			let ciphertext = cipher.encrypt(&key, None, plaintext)?;
			assert_ne!(ciphertext.as_slice(), plaintext);
			assert!(ciphertext.len() >= plaintext.len());

			// Test decryption
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, plaintext);
			Ok(())
		}

		#[test]
		fn test_cipher_properties() {
			let cipher = <$cipher_type>::new();
			assert_eq!(cipher.key_size(), $key_size);
			// Most AES modes use 16-byte blocks
			assert_eq!(cipher.block_size(), 16);
		}

		#[test]
		fn test_wrong_key_size() {
			let cipher = <$cipher_type>::new();
			let wrong_key = vec![0x42u8; $key_size + 1]; // Wrong size
			let plaintext = b"test";

			// Test encryption with wrong key size
			let result = cipher.encrypt(&wrong_key, None, plaintext);
			assert!(matches!(result, Err(CryptoError::InvalidKeySize)));

			// Test decryption with wrong key size
			let fake_ciphertext = vec![0u8; 32];
			let result = cipher.decrypt(&wrong_key, &fake_ciphertext);
			assert!(matches!(result, Err(CryptoError::InvalidKeySize)));
		}

		#[test]
		fn test_random_iv_different_ciphertexts() -> Result<(), Box<dyn core::error::Error>> {
			let cipher = <$cipher_type>::new();
			let key = vec![0x42u8; $key_size];
			let plaintext = b"Same plaintext for randomness test";

			// Encrypt the same plaintext twice
			let ciphertext1 = cipher.encrypt(&key, None, plaintext)?;
			let ciphertext2 = cipher.encrypt(&key, None, plaintext)?;

			// Ciphertexts should be different due to random IV/nonce
			assert_ne!(ciphertext1, ciphertext2);

			// But both should decrypt to the same plaintext
			let decrypted1 = cipher.decrypt(&key, &ciphertext1)?;
			let decrypted2 = cipher.decrypt(&key, &ciphertext2)?;
			assert_eq!(decrypted1, plaintext);
			assert_eq!(decrypted2, plaintext);
			Ok(())
		}

		#[test]
		fn test_various_plaintext_sizes() -> Result<(), Box<dyn core::error::Error>> {
			let cipher = <$cipher_type>::new();
			let key = vec![0x42u8; $key_size];

			// Test empty plaintext
			let empty_plaintext = b"";
			let ciphertext = cipher.encrypt(&key, None, empty_plaintext)?;
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, empty_plaintext);

			// Test single byte
			let single_byte = b"A";
			let ciphertext = cipher.encrypt(&key, None, single_byte)?;
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, single_byte);

			// Test block-aligned data (16 bytes)
			let block_aligned = b"0123456789ABCDEF"; // Exactly 16 bytes
			let ciphertext = cipher.encrypt(&key, None, block_aligned)?;
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, block_aligned);

			// Test non-block-aligned data
			let non_aligned = b"Hello, this is a test message that is not block aligned!";
			let ciphertext = cipher.encrypt(&key, None, non_aligned)?;
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, non_aligned);

			// Test large data
			let large_data = vec![0x55u8; 1024]; // 1KB
			let ciphertext = cipher.encrypt(&key, None, &large_data)?;
			let decrypted = cipher.decrypt(&key, &ciphertext)?;
			assert_eq!(decrypted, large_data);
			Ok(())
		}

		#[test]
		fn test_different_keys_different_results() -> Result<(), Box<dyn core::error::Error>> {
			let plaintext = b"Test message for key difference verification";

			// Create two different keys
			let key1 = vec![0x42u8; $key_size];
			let mut key2 = vec![0x42u8; $key_size];
			key2[0] = 0x43; // Make it different

			let cipher = <$cipher_type>::new();

			// Encrypt with different keys
			let ciphertext1 = cipher.encrypt(&key1, None, plaintext)?;
			let ciphertext2 = cipher.encrypt(&key2, None, plaintext)?;

			// Results should be different
			assert_ne!(ciphertext1, ciphertext2);

			// Each key should decrypt its own ciphertext
			let decrypted1 = cipher.decrypt(&key1, &ciphertext1)?;
			let decrypted2 = cipher.decrypt(&key2, &ciphertext2)?;
			assert_eq!(decrypted1, plaintext);
			assert_eq!(decrypted2, plaintext);

			// Wrong key should fail or produce wrong result
			let wrong_decrypt1 = cipher.decrypt(&key2, &ciphertext1);
			let wrong_decrypt2 = cipher.decrypt(&key1, &ciphertext2);

			// For authenticated encryption (like GCM), this should fail
			// For non-authenticated encryption (like CBC, CTR), this might succeed but produce garbage
			if let Ok(decrypted) = wrong_decrypt1 {
				assert_ne!(decrypted, plaintext);
			}
			if let Ok(decrypted) = wrong_decrypt2 {
				assert_ne!(decrypted, plaintext);
			}
			Ok(())
		}

		#[test]
		fn test_deterministic_with_fixed_iv() -> Result<(), Box<dyn core::error::Error>> {
			let cipher = <$cipher_type>::new();
			let key = vec![0x42u8; $key_size];
			let plaintext = b"Test deterministic encryption";
			let fixed_iv = vec![0x12u8; 16]; // 16-byte IV for most AES modes

			// Encrypt twice with the same fixed IV
			let ciphertext1 = cipher.encrypt(&key, Some(&fixed_iv), plaintext)?;
			let ciphertext2 = cipher.encrypt(&key, Some(&fixed_iv), plaintext)?;

			// Should be identical with fixed IV
			assert_eq!(ciphertext1, ciphertext2);

			// Should decrypt correctly
			let decrypted = cipher.decrypt(&key, &ciphertext1)?;
			assert_eq!(decrypted, plaintext);
			Ok(())
		}
	};
}

// Export the macros for use in other modules
#[cfg(all(test, feature = "encryption"))]
pub(crate) use test_aes_symmetric;
#[cfg(all(test, feature = "encryption"))]
pub(crate) use test_asymmetric_encryption;
#[cfg(test)]
pub(crate) use test_crypto_utils;
#[cfg(all(test, any(feature = "der", feature = "rasn")))]
pub(crate) use test_der;
#[cfg(all(test, feature = "encryption"))]
pub(crate) use test_ecdh;
#[cfg(all(test, feature = "encryption"))]
pub(crate) use test_ecies;
#[cfg(test)]
pub(crate) use test_key_derivation;
#[cfg(all(test, feature = "encryption"))]
pub(crate) use test_key_exchange;
#[cfg(all(test, feature = "signature"))]
pub(crate) use test_signatures;
