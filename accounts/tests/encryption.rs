//! Integration tests for encryption and decryption operations.

use accounts::{Account, Accountable, KeyPairType, Keyable};
use accounts::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
use secrecy::SecretBox;

mod common;
use common::*;

#[test]
fn test_encryption_round_trip_operations() {
	let plaintext = b"Hello, encryption world!";
	let seed_array = create_test_seed_array();

	let secp256k1_account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	if secp256k1_account.supports_encryption() {
		let encrypted = secp256k1_account.encrypt(plaintext).unwrap();
		let decrypted = secp256k1_account.decrypt(&encrypted).unwrap();
		assert_eq!(plaintext, decrypted.as_slice());

		// Verify encryption produces different output each time (should be non-deterministic)
		let encrypted2 = secp256k1_account.encrypt(plaintext).unwrap();
		assert_ne!(encrypted, encrypted2); // Should be different due to randomness

		// But both should decrypt to the same plaintext
		let decrypted2 = secp256k1_account.decrypt(&encrypted2).unwrap();
		assert_eq!(plaintext, decrypted2.as_slice());
	}

	let ed25519_account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ED25519,
	))
	.unwrap();

	if ed25519_account.supports_encryption() {
		let encrypted = ed25519_account.encrypt(plaintext).unwrap();
		let decrypted = ed25519_account.decrypt(&encrypted).unwrap();
		assert_eq!(plaintext, decrypted.as_slice());
	}

	// Test SECP256R1 encryption (should not be supported yet)
	// TODO: Support R1
	let secp256r1_account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new([1u8; 32])), 0)),
		KeyPairType::ECDSASECP256R1,
	))
	.unwrap();

	assert!(!secp256r1_account.supports_encryption());
	assert!(secp256r1_account.encrypt(plaintext).is_err());
}

#[test]
fn test_encryption_message_sizes() {
	let seed_array = create_test_seed_array();
	let account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	if !account.supports_encryption() {
		// Skip if encryption not supported
		return;
	}

	// Test various message sizes
	let test_messages = [
		b"".to_vec(),                  // Empty message
		b"a".to_vec(),                 // Single character
		b"Hello World!".to_vec(),      // Short message
		vec![0u8; 256],                // Medium message (all zeros)
		vec![0x42u8; 1024],            // Larger message (all same byte)
		(0..255).collect::<Vec<u8>>(), // 255 bytes with varying content
	];

	for (i, message) in test_messages.iter().enumerate() {
		let encrypted = account.encrypt(message).unwrap();
		let decrypted = account.decrypt(&encrypted).unwrap();
		assert_eq!(message, &decrypted, "Message {i} failed round-trip");

		// Verify encrypted data is different from original (except possibly empty messages)
		if !message.is_empty() {
			assert_ne!(message, &encrypted.as_slice()[..message.len().min(encrypted.len())]);
		}
	}
}

#[test]
fn test_encryption_error_cases() {
	let seed_array = create_test_seed_array();

	// Test with account that doesn't support encryption
	let secp256r1_account = Account::<KeyECDSASECP256R1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256R1,
	))
	.unwrap();
	assert!(!secp256r1_account.supports_encryption());

	let test_message = b"This should fail";
	let encrypt_result = secp256r1_account.encrypt(test_message);
	assert!(encrypt_result.is_err(), "Encryption should fail for unsupported key types");

	let decrypt_result = secp256r1_account.decrypt(&[1, 2, 3, 4]);
	assert!(decrypt_result.is_err(), "Decryption should fail for unsupported key types");
}

/// Test decryption with invalid data
#[test]
fn test_decryption_invalid_data() {
	let seed_array = create_test_seed_array();
	let account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	if !account.supports_encryption() {
		// Skip if encryption not supported
		return;
	}

	// Test various invalid encrypted data
	let invalid_data_cases = [
		vec![],          // Empty data
		vec![0],         // Single byte
		vec![0; 10],     // Too short
		vec![0xFF; 100], // Invalid but longer data
		vec![0x42; 200], // Different invalid pattern
	];

	for (i, invalid_data) in invalid_data_cases.iter().enumerate() {
		let decrypt_result = account.decrypt(invalid_data);
		assert!(decrypt_result.is_err(), "Decryption should fail with invalid data case {i}");
	}
}

#[test]
fn test_encryption_nondeterministic() {
	let seed_array = create_test_seed_array();
	let account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(
		Keyable::Seed((SecretBox::new(Box::new(seed_array)), 0)),
		KeyPairType::ECDSASECP256K1,
	))
	.unwrap();

	if !account.supports_encryption() {
		// Skip if encryption not supported
		return;
	}

	let message = b"Test message for determinism check";
	let mut encryptions = Vec::new();

	// Create multiple encryptions of the same message
	for _ in 0..5 {
		let encrypted = account.encrypt(message).unwrap();
		encryptions.push(encrypted);
	}

	// All encryptions should be different (non-deterministic)
	for i in 0..encryptions.len() {
		for j in (i + 1)..encryptions.len() {
			assert_ne!(
				encryptions[i], encryptions[j],
				"Encryption {i} and {j} should be different (non-deterministic)"
			);
		}
	}

	// But all should decrypt to the same original message
	for (i, encrypted) in encryptions.iter().enumerate() {
		let decrypted = account.decrypt(encrypted).unwrap();
		assert_eq!(message, decrypted.as_slice(), "Decryption {i} should match original");
	}
}
