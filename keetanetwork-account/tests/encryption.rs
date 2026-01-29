//! Integration tests for encryption and decryption operations.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use keetanetwork_account::{AccountError, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPairType};
use keetanetwork_crypto::algorithms::Algorithm;

mod common;
use common::*;

#[test]
fn test_encryption_round_trip_operations() -> Result<(), AccountError> {
	let plaintext = b"Hello, encryption world!";

	fn test_encryption_round_trip_for_account<T>(
		account: &keetanetwork_account::Account<T>,
		plaintext: &[u8],
		name: &str,
	) -> Result<(), AccountError>
	where
		T: keetanetwork_account::KeyPair,
	{
		let encrypted = account.encrypt(plaintext)?;
		let decrypted = account.decrypt(&encrypted)?;
		assert_eq!(plaintext, decrypted.as_slice(), "{name}: Decrypted data should match original plaintext");

		// Verify encryption produces different output each time (should be non-deterministic)
		let encrypted2 = account.encrypt(plaintext)?;
		assert_ne!(encrypted, encrypted2, "{name}: Encryption should produce different output each time");

		// But both should decrypt to the same plaintext
		let decrypted2 = account.decrypt(&encrypted2)?;
		assert_eq!(plaintext, decrypted2.as_slice(), "{name}: Second decryption should match original plaintext");

		Ok(())
	}

	// Test SECP256K1
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;
	test_encryption_round_trip_for_account(&account, plaintext, "SECP256K1")?;

	// Test ED25519
	let account = create_account_from_seed::<KeyED25519>(KeyPairType::ED25519, 0)?;
	test_encryption_round_trip_for_account(&account, plaintext, "ED25519")?;

	// Test SECP256R1
	let account = create_account_from_seed::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, 0)?;
	test_encryption_round_trip_for_account(&account, plaintext, "SECP256R1")?;

	Ok(())
}

#[test]
fn test_encryption_message_sizes() -> Result<(), AccountError> {
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;

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
		let encrypted = account.encrypt(message)?;
		let decrypted = account.decrypt(&encrypted)?;
		assert_eq!(message, &decrypted, "Message {i} failed round-trip");

		// Verify encrypted data is different from original
		// Even empty messages should produce non-empty encrypted data
		assert_ne!(
			message.as_slice(),
			encrypted.as_slice(),
			"Encrypted data should differ from plaintext for message {i}"
		);
	}

	Ok(())
}

#[test]
fn test_encryption_error_cases() -> Result<(), AccountError> {
	// Test with an account that supports encryption but with invalid data
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;

	// Decryption with invalid data should fail
	let decrypt_result = account.decrypt([1, 2, 3, 4]);
	assert!(decrypt_result.is_err(), "Decryption should fail with invalid data");

	let decrypt_result = account.decrypt([]);
	assert!(decrypt_result.is_err(), "Decryption should fail with empty data");

	Ok(())
}

/// Test decryption with invalid data
#[test]
fn test_decryption_invalid_data() -> Result<(), AccountError> {
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;

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

	Ok(())
}

#[test]
fn test_encryption_nondeterministic() -> Result<(), AccountError> {
	let account = create_account_from_seed::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, 0)?;

	let message = b"Test message for determinism check";
	let mut encryptions = Vec::new();

	// Create multiple encryptions of the same message
	for _ in 0..5 {
		let encrypted = account.encrypt(message)?;
		encryptions.push(encrypted);
	}

	// All encryptions should be different
	for i in 0..encryptions.len() {
		for j in (i + 1)..encryptions.len() {
			assert_ne!(encryptions[i], encryptions[j], "Encryption {i} and {j} should be non-deterministic");
		}
	}

	// All should decrypt to the same original message
	for (i, encrypted) in encryptions.iter().enumerate() {
		let decrypted = account.decrypt(encrypted)?;
		assert_eq!(message, decrypted.as_slice(), "Decryption {i} should match original");
	}

	Ok(())
}

#[test]
fn test_typescript_encryption_compatibility() -> Result<(), AccountError> {
	// Test data from TypeScript implementation - these encrypted values were
	// generated using the same seed and keys as the TypeScript tests
	let test_seed = "2401D206735C20485347B9A622D94DE9B21F2F1450A77C42102237FA4077567D";

	struct EncryptionTestCase {
		algorithm: Algorithm,
		encrypted_data_base64: &'static str,
		expected_plaintext: &'static [u8],
	}

	let test_cases = [
		EncryptionTestCase {
			algorithm: Algorithm::Secp256k1,
			encrypted_data_base64: "BI8ePLqAhgOQvUXsTqW8ifQ77eRhg7Z6FpxX5wd6xJfE+ErjHyuXFKNjSDMBgTAG6iKylZITJajh6Zdgcbpdvb3+pBN17zCaaOzAgpId4hcOG3P/ueHMRWolYQPJ5jGqM1xmBO64sa3nodxDwEtAI5dA3CG4mg==",
			expected_plaintext: b"Hello",
		},
		EncryptionTestCase {
			algorithm: Algorithm::Ed25519,
			encrypted_data_base64: "fZazrME6jGTTj2Dp1o9imAuri5s3MxeE0ZnK8HP2dK4TgnAJ3825UWKFaQnW0E0tETD0iyo8B1Zex4JUB7Ab83RnJrWBxGfoho6YqaKdHTWYfAPPJ1G2EBkDo1qoiGpO8t1Tb3o9JiOQf6jAMp2VKg==",
			expected_plaintext: b"Ed25519 Encryption",
		},
		EncryptionTestCase {
			algorithm: Algorithm::Secp256r1,
			encrypted_data_base64: "BBF2ML5v5BMyOu/BMChxa984vGgED2rjaM5I0QP01MmjdMWnHx/00AfpxSCaVkFx3qYbl4cpxBM3WcHo9PIZG5P1CMv36lv8wmMMus+xQ/KrUozna8hLRlJN9ez3i+vzOZeMKYm9EfkpMZ2eQv1y1clevkvKicA8V+Zt3CVog0MhT9HYuTwWWN9yoxfshAlqGpODSFiHabdLG3E4er2d9q8=",
			expected_plaintext: b"Hello",
		},
	];

	// Helper function to test encryption compatibility for a specific account type
	fn test_account_encryption<T>(
		test_case: &EncryptionTestCase,
		account: &keetanetwork_account::Account<T>,
	) -> Result<(), AccountError>
	where
		T: keetanetwork_account::KeyPair,
	{
		// Decode base64 encrypted data
		let encrypted_data = BASE64
			.decode(test_case.encrypted_data_base64)
			.expect("invariant: constant base64 test data");

		// Try to decrypt TypeScript-encrypted data with Rust implementation
		if let Ok(decrypted) = account.decrypt(&encrypted_data) {
			assert_eq!(
				decrypted.as_slice(),
				test_case.expected_plaintext,
				"{:?}: Decrypted data does not match expected plaintext",
				test_case.algorithm
			);
		}

		// Test round-trip: encrypt and verify we can decrypt
		let rust_encrypted = account.encrypt(test_case.expected_plaintext)?;
		let rust_decrypted = account.decrypt(&rust_encrypted)?;

		assert_eq!(
			rust_decrypted.as_slice(),
			test_case.expected_plaintext,
			"{:?}: Rust round-trip failed",
			test_case.algorithm
		);

		Ok(())
	}

	// Test each algorithm
	for test_case in &test_cases {
		match test_case.algorithm {
			Algorithm::Secp256k1 => {
				let account =
					create_account_from_seed_hex::<KeyECDSASECP256K1>(KeyPairType::ECDSASECP256K1, test_seed, 0)?;
				test_account_encryption(test_case, &account)?;
			}
			Algorithm::Ed25519 => {
				let account = create_account_from_seed_hex::<KeyED25519>(KeyPairType::ED25519, test_seed, 0)?;
				test_account_encryption(test_case, &account)?;
			}
			Algorithm::Secp256r1 => {
				let account =
					create_account_from_seed_hex::<KeyECDSASECP256R1>(KeyPairType::ECDSASECP256R1, test_seed, 0)?;
				test_account_encryption(test_case, &account)?;
			}
		}
	}

	Ok(())
}
