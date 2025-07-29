//! Integration tests for encryption and decryption operations.

use accounts::{KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPairType};

mod common;
use common::*;

#[test]
fn test_encryption_round_trip_operations() {
	let plaintext = b"Hello, encryption world!";

	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0);

	if account.supports_encryption() {
		let encrypted = account.encrypt(plaintext).unwrap();
		let decrypted = account.decrypt(&encrypted).unwrap();
		assert_eq!(plaintext, decrypted.as_slice(), "Decrypted data should match original plaintext");

		// Verify encryption produces different output each time (should be non-deterministic)
		let encrypted2 = account.encrypt(plaintext).unwrap();
		assert_ne!(encrypted, encrypted2, "Encryption should produce different output each time");
		// But both should decrypt to the same plaintext
		let decrypted2 = account.decrypt(&encrypted2).unwrap();
		assert_eq!(plaintext, decrypted2.as_slice(), "Decrypted data should match original plaintext");
	}

	let account = create_account_from_seed::<KeyED25519>(KeyPairType::ED25519, 0);

	if account.supports_encryption() {
		let encrypted = account.encrypt(plaintext).unwrap();
		let decrypted = account.decrypt(&encrypted).unwrap();
		assert_eq!(plaintext, decrypted.as_slice(), "ED25519 encryption/decryption failed");
	}

	// Test SECP256R1 encryption (should not be supported yet)
	// TODO: Support R1
	let account = create_account_from_seed::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, 0);

	assert!(!account.supports_encryption());
	assert!(account.encrypt(plaintext).is_err());
}

#[test]
fn test_encryption_message_sizes() {
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0);

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
	// Test with account that doesn't support encryption
	let account = create_account_from_seed::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, 0);
	assert!(!account.supports_encryption());

	let test_message = b"This should fail";
	let encrypt_result = account.encrypt(test_message);
	assert!(encrypt_result.is_err(), "Encryption should fail for unsupported key types");

	let decrypt_result = account.decrypt(&[1, 2, 3, 4]);
	assert!(decrypt_result.is_err(), "Decryption should fail for unsupported key types");
}

/// Test decryption with invalid data
#[test]
fn test_decryption_invalid_data() {
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0);

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
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0);

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
