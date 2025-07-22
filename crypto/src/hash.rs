//! Hash abstraction module for KeetaNet cryptographic operations
//!
//! This module provides a flexible abstraction over different hash algorithms,
//! similar to how the cryptographic algorithms are abstracted.
//!
//! # Examples
//!
//! ```rust
//! use crypto::{HashAlgorithm, hash_default, hash, hash_array};
//!
//! let data = b"hello world";
//!
//! // Use default algorithm (SHA3-256)
//! let default_hash = hash_default(data); // [u8; 32]
//! let full_hash: [u8; 32] = hash(data, None).unwrap();
//! let truncated: [u8; 16] = hash(data, None).unwrap();
//!
//! // Use specific algorithms with const generics
//! let sha2_256: [u8; 32] = hash(data, Some(HashAlgorithm::Sha2_256)).unwrap();
//! let sha2_512: [u8; 64] = hash(data, Some(HashAlgorithm::Sha2_512)).unwrap();
//! let sha2_512_truncated: [u8; 32] = hash(data, Some(HashAlgorithm::Sha2_512)).unwrap();
//!
//! // Alternative array API (same as hash function)
//! let array_result: [u8; 32] = hash_array(data, None).unwrap();
//! ```

use sha2::{Sha256, Sha512};
use sha3::{Digest, Sha3_256};

use crate::error::CryptoError;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
	/// SHA3-256 (default for KeetaNet)
	Sha3_256,
	/// SHA2-256
	Sha2_256,
	/// SHA2-512
	Sha2_512,
}

impl HashAlgorithm {
	/// Get the algorithm name as a string
	pub fn name(&self) -> &'static str {
		match self {
			HashAlgorithm::Sha3_256 => "sha3-256",
			HashAlgorithm::Sha2_256 => "sha2-256",
			HashAlgorithm::Sha2_512 => "sha2-512",
		}
	}

	/// Get the output length in bytes
	pub fn length(&self) -> usize {
		match self {
			HashAlgorithm::Sha3_256 => 32,
			HashAlgorithm::Sha2_256 => 32,
			HashAlgorithm::Sha2_512 => 64,
		}
	}

	/// Hash data using this algorithm
	pub fn hash(&self, data: &[u8]) -> Vec<u8> {
		match self {
			HashAlgorithm::Sha3_256 => {
				let mut hasher = Sha3_256::new();
				hasher.update(data);
				hasher.finalize().to_vec()
			}
			HashAlgorithm::Sha2_256 => {
				let mut hasher = Sha256::new();
				hasher.update(data);
				hasher.finalize().to_vec()
			}
			HashAlgorithm::Sha2_512 => {
				let mut hasher = Sha512::new();
				hasher.update(data);
				hasher.finalize().to_vec()
			}
		}
	}

	/// Hash data and return as a fixed-size array
	pub fn hash_array<const N: usize>(&self, data: &[u8]) -> Result<[u8; N], CryptoError> {
		if N != self.length() {
			return Err(CryptoError::InvalidLength);
		}

		let hash = self.hash(data);
		let mut array = [0u8; N];
		array.copy_from_slice(&hash);
		Ok(array)
	}

	/// Hash data and truncate to specified length
	pub fn hash_truncated(&self, data: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
		if length > self.length() {
			return Err(CryptoError::InvalidLength);
		}

		let hash = self.hash(data);
		Ok(hash[..length].to_vec())
	}
}

/// Default hash algorithm for KeetaNet (SHA3-256)
pub const DEFAULT_HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha3_256;

/// Hash function name to use with key derivation and public key checksums
pub const HASH_FUNCTION_NAME: &str = "sha3-256";

/// Length of the hash function in bytes
pub const HASH_FUNCTION_LENGTH: usize = 32;

/// Hash some data with optional algorithm and optional fixed length
///
/// This function provides a flexible interface for hashing data.
/// - If `algorithm` is None, uses the default algorithm (SHA3-256)
/// - Returns a fixed-size array of length N
/// - For truncation, N must be <= algorithm's output length
pub fn hash<const N: usize>(data: &[u8], algorithm: Option<HashAlgorithm>) -> Result<[u8; N], CryptoError> {
	let algo = algorithm.unwrap_or(DEFAULT_HASH_ALGORITHM);

	if N > algo.length() {
		return Err(CryptoError::InvalidLength);
	}

	let hash_result = algo.hash(data);
	let mut array = [0u8; N];
	array.copy_from_slice(&hash_result[..N]);
	Ok(array)
}

/// Hash some data using the default algorithm, returning the full hash
pub fn hash_default(data: &[u8]) -> [u8; 32] {
	DEFAULT_HASH_ALGORITHM.hash_array::<32>(data).expect("SHA3-256 should always produce 32 bytes")
}

/// Hash some data using an optional algorithm, returning a fixed-size array
///
/// If algorithm is None, uses the default algorithm (SHA3-256) and returns
/// a 32-byte array.
///
/// For other algorithms, returns an array of the appropriate size:
/// - SHA3-256 and SHA2-256: 32 bytes
/// - SHA2-512: 64 bytes
pub fn hash_array<const N: usize>(data: &[u8], algorithm: Option<HashAlgorithm>) -> Result<[u8; N], CryptoError> {
	let algo = algorithm.unwrap_or(DEFAULT_HASH_ALGORITHM);
	algo.hash_array::<N>(data)
}

/// Get the hash function name
pub fn default_hash_algorithm() -> &'static str {
	HASH_FUNCTION_NAME
}

/// Get the hash function length in bytes
pub fn default_hash_algorithm_length() -> usize {
	HASH_FUNCTION_LENGTH
}

#[cfg(test)]
mod tests {
	use super::*;

	// Test data for different algorithms with comprehensive test cases
	struct HashTestCase {
		algorithm: HashAlgorithm,
		name: &'static str,
		length: usize,
		// Expected hashes for different inputs
		expected_hello_world: &'static str,
		expected_empty: &'static str,
		expected_test_data: &'static str,
	}

	const HASH_TEST_CASES: &[HashTestCase] = &[
		HashTestCase {
			algorithm: HashAlgorithm::Sha3_256,
			name: "sha3-256",
			length: 32,
			expected_hello_world: "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
			expected_empty: "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
			expected_test_data: "fc88e0ac33ff105e376f4ece95fb06925d5ab20080dbe3aede7dd47e45dfd931",
		},
		HashTestCase {
			algorithm: HashAlgorithm::Sha2_256,
			name: "sha2-256",
			length: 32,
			expected_hello_world: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			expected_empty: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected_test_data: "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
		},
		HashTestCase {
			algorithm: HashAlgorithm::Sha2_512,
			name: "sha2-512",
			length: 64,
			expected_hello_world: "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
			expected_empty: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			expected_test_data: "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
		},
	];

	const TEST_INPUTS: &[(&[u8], &str)] =
		&[(b"hello world", "hello_world"), (b"", "empty"), (b"test data", "test_data")];

	#[test]
	fn test_algorithm_properties() {
		for test_case in HASH_TEST_CASES {
			// Test basic properties
			assert_eq!(test_case.algorithm.name(), test_case.name);
			assert_eq!(test_case.algorithm.length(), test_case.length);

			// Test that hash produces correct length
			for &(input, _) in TEST_INPUTS {
				let result = test_case.algorithm.hash(input);
				assert_eq!(result.len(), test_case.length);
			}
		}

		// Verify different algorithms produce different results
		let test_data = b"hello world";
		let results: Vec<_> = HASH_TEST_CASES.iter().map(|tc| tc.algorithm.hash(test_data)).collect();
		for i in 0..results.len() {
			for j in i + 1..results.len() {
				assert_ne!(
					results[i], results[j],
					"Algorithms {} and {} should produce different results",
					HASH_TEST_CASES[i].name, HASH_TEST_CASES[j].name
				);
			}
		}
	}

	#[test]
	fn test_expected_hash_values() {
		for test_case in HASH_TEST_CASES {
			// Test expected hash values for known inputs
			assert_eq!(hex::encode(test_case.algorithm.hash(b"hello world")), test_case.expected_hello_world);
			assert_eq!(hex::encode(test_case.algorithm.hash(b"")), test_case.expected_empty);
			assert_eq!(hex::encode(test_case.algorithm.hash(b"test data")), test_case.expected_test_data);
		}
	}

	#[test]
	fn test_hash_array_functionality() {
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				// Test valid array length (matching algorithm's output size)
				if test_case.length == 32 {
					let array: [u8; 32] = test_case.algorithm.hash_array(input).unwrap();
					let vec_result = test_case.algorithm.hash(input);
					assert_eq!(array.to_vec(), vec_result);

					// Test invalid array length
					let invalid: Result<[u8; 16], CryptoError> = test_case.algorithm.hash_array(input);
					assert_eq!(invalid.unwrap_err(), CryptoError::InvalidLength);
				} else if test_case.length == 64 {
					let array: [u8; 64] = test_case.algorithm.hash_array(input).unwrap();
					let vec_result = test_case.algorithm.hash(input);
					assert_eq!(array.to_vec(), vec_result);

					// Test invalid array length
					let invalid: Result<[u8; 32], CryptoError> = test_case.algorithm.hash_array(input);
					assert_eq!(invalid.unwrap_err(), CryptoError::InvalidLength);
				}
			}
		}
	}

	#[test]
	fn test_truncation() {
		for test_case in HASH_TEST_CASES {
			let full_hash = test_case.algorithm.hash(b"test data");

			// Test various truncation lengths
			let test_lengths: Vec<usize> =
				(1..=test_case.length).step_by(if test_case.length == 64 { 8 } else { 4 }).collect();

			for &length in &test_lengths {
				let truncated = test_case.algorithm.hash_truncated(b"test data", length).unwrap();
				assert_eq!(truncated.len(), length);
				assert_eq!(truncated, &full_hash[..length]);
			}

			// Test invalid truncation length
			let invalid = test_case.algorithm.hash_truncated(b"test data", test_case.length + 1);
			assert_eq!(invalid.unwrap_err(), CryptoError::InvalidLength);

			// Test zero-length truncation
			let zero_length = test_case.algorithm.hash_truncated(b"test data", 0).unwrap();
			assert!(zero_length.is_empty());
		}
	}

	#[test]
	fn test_main_hash_api() {
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				// Test main hash function with appropriate const generic
				if test_case.length == 32 {
					let result: [u8; 32] = hash(input, Some(test_case.algorithm)).unwrap();
					let expected = test_case.algorithm.hash(input);
					assert_eq!(result.to_vec(), expected);

					// Test truncation
					let truncated: [u8; 16] = hash(input, Some(test_case.algorithm)).unwrap();
					assert_eq!(truncated[..], expected[..16]);
				} else if test_case.length == 64 {
					let result: [u8; 64] = hash(input, Some(test_case.algorithm)).unwrap();
					let expected = test_case.algorithm.hash(input);
					assert_eq!(result.to_vec(), expected);

					// Test truncation
					let truncated: [u8; 32] = hash(input, Some(test_case.algorithm)).unwrap();
					assert_eq!(truncated[..], expected[..32]);
				}
			}
		}

		// Test invalid length
		let invalid: Result<[u8; 100], CryptoError> = hash(b"test", Some(HashAlgorithm::Sha3_256));
		assert_eq!(invalid.unwrap_err(), CryptoError::InvalidLength);
	}

	#[test]
	fn test_default_behavior() {
		for &(input, _) in TEST_INPUTS {
			// All default functions should produce the same result
			let hash_default_result = hash_default(input);
			let hash_none: [u8; 32] = hash(input, None).unwrap();
			let hash_array_none: [u8; 32] = hash_array(input, None).unwrap();

			assert_eq!(hash_default_result, hash_none);
			assert_eq!(hash_default_result, hash_array_none);

			// Should match explicit SHA3-256
			let explicit_sha3 = HashAlgorithm::Sha3_256.hash_array::<32>(input).unwrap();
			assert_eq!(hash_default_result, explicit_sha3);
		}
	}

	#[test]
	fn test_consistency() {
		// Test that multiple calls produce identical results
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				let result1 = test_case.algorithm.hash(input);
				let result2 = test_case.algorithm.hash(input);
				let result3 = test_case.algorithm.hash(input);

				assert_eq!(result1, result2);
				assert_eq!(result2, result3);
			}
		}
	}

	#[test]
	fn test_api_equivalence() {
		let test_data = b"hello world";

		// Test that hash and hash_array are equivalent
		let hash_result: [u8; 32] = hash(test_data, None).unwrap();
		let hash_array_result: [u8; 32] = hash_array(test_data, None).unwrap();
		assert_eq!(hash_result, hash_array_result);

		// Test with different algorithms
		for test_case in HASH_TEST_CASES {
			if test_case.length == 32 {
				let hash_result: [u8; 32] = hash(test_data, Some(test_case.algorithm)).unwrap();
				let hash_array_result: [u8; 32] = hash_array(test_data, Some(test_case.algorithm)).unwrap();
				assert_eq!(hash_result, hash_array_result);
			}
		}
	}

	#[test]
	fn test_constants_and_compatibility() {
		assert_eq!(default_hash_algorithm(), "sha3-256");
		assert_eq!(default_hash_algorithm_length(), 32);
		assert_eq!(DEFAULT_HASH_ALGORITHM, HashAlgorithm::Sha3_256);
		assert_eq!(HASH_FUNCTION_NAME, "sha3-256");
		assert_eq!(HASH_FUNCTION_LENGTH, 32);

		// Verify constants are consistent
		assert_eq!(default_hash_algorithm(), HASH_FUNCTION_NAME);
		assert_eq!(default_hash_algorithm_length(), HASH_FUNCTION_LENGTH);
		assert_eq!(DEFAULT_HASH_ALGORITHM.name(), HASH_FUNCTION_NAME);
		assert_eq!(DEFAULT_HASH_ALGORITHM.length(), HASH_FUNCTION_LENGTH);
	}
}
