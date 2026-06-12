//! Hash abstraction module for KeetaNet cryptographic operations.
//!
//! This module provides a flexible abstraction over different hash algorithms.

use core::fmt::{Display, Formatter, Result as FmtResult};
use core::str::FromStr;

use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Digest, Sha3_256};

use crate::constants::*;
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
	/// SHA-1
	/// For X.509 Subject Key Identifier per RFC 5280
	/// See: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2>
	Sha1,
}

impl HashAlgorithm {
	/// Get the algorithm name as a string
	pub fn name(&self) -> &'static str {
		match self {
			HashAlgorithm::Sha3_256 => "sha3-256",
			HashAlgorithm::Sha2_256 => "sha2-256",
			HashAlgorithm::Sha2_512 => "sha2-512",
			HashAlgorithm::Sha1 => "sha1",
		}
	}

	/// Get the output length in bytes
	pub fn length(&self) -> usize {
		match self {
			HashAlgorithm::Sha3_256 => 32,
			HashAlgorithm::Sha2_256 => 32,
			HashAlgorithm::Sha2_512 => 64,
			HashAlgorithm::Sha1 => 20,
		}
	}

	/// Hash data using this algorithm
	pub fn hash(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
		let data = data.as_ref();
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
			HashAlgorithm::Sha1 => {
				let mut hasher = Sha1::new();
				hasher.update(data);
				hasher.finalize().to_vec()
			}
		}
	}

	/// Hash data and return as a fixed-size array
	pub fn hash_array<const N: usize>(&self, data: impl AsRef<[u8]>) -> Result<[u8; N], CryptoError> {
		if N != self.length() {
			return Err(CryptoError::InvalidLength {
				message: format!("Expected length: {}, got: {}", N, self.length()),
			});
		}

		let hash = self.hash(data);
		let mut array = [0u8; N];
		array.copy_from_slice(&hash);
		Ok(array)
	}

	/// Hash data and truncate to specified length
	pub fn hash_truncated(&self, data: impl AsRef<[u8]>, length: usize) -> Result<Vec<u8>, CryptoError> {
		if length > self.length() {
			return Err(CryptoError::InvalidLength {
				message: format!("Expected length: {}, got: {}", length, self.length()),
			});
		}

		let hash = self.hash(data);
		Ok(hash[..length].to_vec())
	}
}

/// Hash some data with optional algorithm and optional fixed length.
///
/// This function provides a flexible interface for hashing data.
/// - If `algorithm` is None, uses the default algorithm (SHA3-256)
/// - Returns a fixed-size array of length N
/// - For truncation, N must be <= algorithm's output length
pub fn hash<const N: usize>(data: impl AsRef<[u8]>, algorithm: Option<HashAlgorithm>) -> Result<[u8; N], CryptoError> {
	let algo = algorithm.unwrap_or(DEFAULT_HASH_ALGORITHM);
	if N > algo.length() {
		return Err(CryptoError::InvalidLength { message: format!("Expected length: {}, got: {}", N, algo.length()) });
	}

	let hash_result = algo.hash(data);
	let mut array = [0u8; N];
	array.copy_from_slice(&hash_result[..N]);

	Ok(array)
}

/// Hash some data using the default algorithm, returning the full hash.
pub fn hash_default(data: impl AsRef<[u8]>) -> [u8; 32] {
	DEFAULT_HASH_ALGORITHM
		.hash_array::<32>(data)
		.expect("invariant: SHA3-256 always produces 32 bytes")
}

/// Hash some data using an optional algorithm, returning a fixed-size array.
///
/// If algorithm is None, uses the default algorithm (SHA3-256) and returns
/// a 32-byte array.
///
/// For other algorithms, returns an array of the appropriate size:
/// - SHA3-256 and SHA2-256: 32 bytes
/// - SHA2-512: 64 bytes
pub fn hash_array<const N: usize>(
	data: impl AsRef<[u8]>,
	algorithm: Option<HashAlgorithm>,
) -> Result<[u8; N], CryptoError> {
	let algo = algorithm.unwrap_or(DEFAULT_HASH_ALGORITHM);

	algo.hash_array::<N>(data)
}

/// A 32-byte block hash produced by the default hash algorithm (SHA3-256).
///
/// This is the canonical hash type for blocks and block-derived values such
/// as account opening hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockHash([u8; HASH_FUNCTION_LENGTH]);

impl BlockHash {
	/// Compute the account opening hash from a raw public key
	/// (without the key type prefix byte).
	pub fn opening(raw_public_key: impl AsRef<[u8]>) -> Self {
		Self(hash_default(raw_public_key))
	}

	/// Borrow the hash as a fixed-size byte array.
	pub fn as_bytes(&self) -> &[u8; HASH_FUNCTION_LENGTH] {
		&self.0
	}
}

impl From<[u8; HASH_FUNCTION_LENGTH]> for BlockHash {
	fn from(bytes: [u8; HASH_FUNCTION_LENGTH]) -> Self {
		Self(bytes)
	}
}

impl From<BlockHash> for [u8; HASH_FUNCTION_LENGTH] {
	fn from(hash: BlockHash) -> Self {
		hash.0
	}
}

impl AsRef<[u8]> for BlockHash {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for BlockHash {
	type Error = CryptoError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		let array: [u8; HASH_FUNCTION_LENGTH] = bytes.try_into()?;
		Ok(Self(array))
	}
}

impl Display for BlockHash {
	fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
		write!(f, "{}", hex::encode_upper(self.0))
	}
}

impl FromStr for BlockHash {
	type Err = CryptoError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut bytes = [0u8; HASH_FUNCTION_LENGTH];
		hex::decode_to_slice(s, &mut bytes)?;
		Ok(Self(bytes))
	}
}

/// Types that can be hashed into a [`BlockHash`] using the default algorithm.
pub trait Hashable {
	/// Compute the hash of this value.
	fn hash(&self) -> BlockHash;
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
		HashTestCase {
			algorithm: HashAlgorithm::Sha1,
			name: "sha1",
			length: 20,
			expected_hello_world: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
			expected_empty: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			expected_test_data: "f48dd853820860816c75d54d0f584dc863327a7c",
		},
	];

	const TEST_INPUTS: &[(&[u8], &str)] =
		&[(b"hello world", "hello_world"), (b"", "empty"), (b"test data", "test_data")];

	/// Helper function to get expected hash value for a test case and input
	fn get_expected_hash(test_case: &HashTestCase, input: &[u8]) -> &'static str {
		match input {
			b"hello world" => test_case.expected_hello_world,
			b"" => test_case.expected_empty,
			b"test data" => test_case.expected_test_data,
			_ => panic!("Unexpected input for test case"),
		}
	}

	/// Helper macro to test hash array functionality for different sizes
	macro_rules! with_hash_size {
		($length:expr, $test_fn:ident, $($args:expr),*) => {
			match $length {
				20 => $test_fn::<20>($($args),*)?,
				32 => $test_fn::<32>($($args),*)?,
				64 => $test_fn::<64>($($args),*)?,
				_ => return Err(CryptoError::InvalidLength { message: format!("Unsupported hash length: {}", $length) }),
			}
		};
	}

	/// Generic helper function for testing hash array functionality
	fn test_hash_array_for_size<const N: usize>(
		algorithm: HashAlgorithm,
		input: &[u8],
		expected_vec: &[u8],
	) -> Result<(), CryptoError> {
		let array: [u8; N] = algorithm.hash_array(input)?;
		assert_eq!(array.to_vec(), expected_vec);
		Ok(())
	}

	/// Generic helper function for testing invalid hash array sizes
	fn test_invalid_hash_array<const N: usize>(algorithm: HashAlgorithm, input: &[u8]) {
		let result: Result<[u8; N], CryptoError> = algorithm.hash_array(input);
		assert!(matches!(result.unwrap_err(), CryptoError::InvalidLength { .. }));
	}

	/// Generic helper function for testing main hash API
	fn test_main_hash_for_size<const N: usize>(
		algorithm: HashAlgorithm,
		input: &[u8],
		expected: &[u8],
	) -> Result<(), CryptoError> {
		let result: [u8; N] = hash(input, Some(algorithm))?;
		assert_eq!(result.to_vec(), expected);
		Ok(())
	}

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
		let results: Vec<_> = HASH_TEST_CASES
			.iter()
			.map(|tc| tc.algorithm.hash(test_data))
			.collect();

		for i in 0..results.len() {
			for j in i + 1..results.len() {
				assert_ne!(results[i], results[j]);
			}
		}
	}

	#[test]
	fn test_expected_hash_values() {
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				let expected = get_expected_hash(test_case, input);
				let actual = hex::encode(test_case.algorithm.hash(input));
				assert_eq!(actual, expected, "Hash mismatch for {} with input: {:?}", test_case.name, input);
			}
		}
	}

	#[test]
	fn test_hash_array_functionality() -> Result<(), CryptoError> {
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				// Test valid array length (matching algorithm's output size)
				let vec_result = test_case.algorithm.hash(input);
				with_hash_size!(test_case.length, test_hash_array_for_size, test_case.algorithm, input, &vec_result);

				// Test invalid array length based on algorithm
				match test_case.length {
					20 => test_invalid_hash_array::<16>(test_case.algorithm, input),
					32 => test_invalid_hash_array::<16>(test_case.algorithm, input),
					64 => test_invalid_hash_array::<32>(test_case.algorithm, input),
					_ => {
						return Err(CryptoError::InvalidLength {
							message: format!("Unexpected hash length: {}", test_case.length),
						})
					}
				}
			}
		}

		Ok(())
	}

	#[test]
	fn test_truncation() -> Result<(), CryptoError> {
		for test_case in HASH_TEST_CASES {
			let full_hash = test_case.algorithm.hash(b"test data");

			// Test various truncation lengths
			let test_lengths: Vec<usize> = (1..=test_case.length)
				.step_by(if test_case.length == 64 {
					8
				} else {
					4
				})
				.collect();

			for &length in &test_lengths {
				let truncated = test_case.algorithm.hash_truncated(b"test data", length)?;
				assert_eq!(truncated.len(), length);
				assert_eq!(truncated, &full_hash[..length]);
			}

			// Test invalid truncation length
			let invalid = test_case
				.algorithm
				.hash_truncated(b"test data", test_case.length + 1);
			assert!(matches!(invalid, Err(CryptoError::InvalidLength { .. })));

			// Test zero-length truncation
			let zero_length = test_case.algorithm.hash_truncated(b"test data", 0)?;
			assert!(zero_length.is_empty());
		}

		Ok(())
	}

	#[test]
	fn test_main_hash_api() -> Result<(), CryptoError> {
		for test_case in HASH_TEST_CASES {
			for &(input, _) in TEST_INPUTS {
				let expected = test_case.algorithm.hash(input);

				// Test main hash function with appropriate const generic
				with_hash_size!(test_case.length, test_main_hash_for_size, test_case.algorithm, input, &expected);

				// Test truncation based on algorithm
				match test_case.length {
					20 => {
						let truncated: [u8; 16] = hash(input, Some(test_case.algorithm))?;
						assert_eq!(truncated[..], expected[..16]);
					}
					32 => {
						let truncated: [u8; 16] = hash(input, Some(test_case.algorithm))?;
						assert_eq!(truncated[..], expected[..16]);
					}
					64 => {
						let truncated: [u8; 32] = hash(input, Some(test_case.algorithm))?;
						assert_eq!(truncated[..], expected[..32]);
					}
					_ => {
						return Err(CryptoError::InvalidLength {
							message: format!("Unexpected hash length: {}", test_case.length),
						})
					}
				}
			}
		}

		// Test invalid length
		let invalid: Result<[u8; 100], CryptoError> = hash(b"test", Some(HashAlgorithm::Sha3_256));
		assert!(matches!(invalid, Err(CryptoError::InvalidLength { .. })));

		Ok(())
	}

	#[test]
	fn test_default_behavior() -> Result<(), CryptoError> {
		for &(input, _) in TEST_INPUTS {
			// All default functions should produce the same result
			let hash_default_result = hash_default(input);
			let hash_none: [u8; 32] = hash(input, None)?;
			let hash_array_none: [u8; 32] = hash_array(input, None)?;
			assert_eq!(hash_default_result, hash_none);
			assert_eq!(hash_default_result, hash_array_none);

			// Should match explicit SHA3-256
			let explicit_sha3 = HashAlgorithm::Sha3_256.hash_array::<32>(input)?;
			assert_eq!(hash_default_result, explicit_sha3);
		}

		Ok(())
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
	fn test_api_equivalence() -> Result<(), CryptoError> {
		let test_data = b"hello world";

		// Test that hash and hash_array are equivalent for default algorithm
		let hash_result: [u8; 32] = hash(test_data, None)?;
		let hash_array_result: [u8; 32] = hash_array(test_data, None)?;
		assert_eq!(hash_result, hash_array_result);

		// Test with different algorithms using helper functions
		for test_case in HASH_TEST_CASES {
			with_hash_size!(test_case.length, test_api_equivalence_for_size, test_case.algorithm, test_data);
		}

		Ok(())
	}

	/// Helper function for testing API equivalence for a specific size
	fn test_api_equivalence_for_size<const N: usize>(
		algorithm: HashAlgorithm,
		test_data: &[u8],
	) -> Result<(), CryptoError> {
		let hash_result: [u8; N] = hash(test_data, Some(algorithm))?;
		let hash_array_result: [u8; N] = hash_array(test_data, Some(algorithm))?;
		assert_eq!(hash_result, hash_array_result);

		Ok(())
	}

	#[test]
	fn test_block_hash_roundtrip() {
		let hash = BlockHash::from(hash_default(b"test data"));
		let text = hash.to_string();
		let parsed: BlockHash = text.parse().unwrap();
		assert_eq!(parsed, hash);
		assert_eq!(text, text.to_uppercase());
		assert_eq!(hash.as_ref().len(), 32);
		assert_eq!(<[u8; 32]>::from(hash), *hash.as_bytes());
	}

	#[test]
	fn test_block_hash_parse_lowercase() {
		let hash = BlockHash::from(hash_default(b"abc"));
		let parsed: BlockHash = hash.to_string().to_lowercase().parse().unwrap();
		assert_eq!(parsed, hash);
	}

	#[test]
	fn test_block_hash_parse_invalid() {
		assert!(matches!("zz".parse::<BlockHash>(), Err(CryptoError::InvalidInput)));
		assert!(matches!("aabb".parse::<BlockHash>(), Err(CryptoError::InvalidInput)));
		assert!(matches!(BlockHash::try_from([0u8; 16].as_slice()), Err(CryptoError::InvalidKeySize)));
	}

	#[test]
	fn test_block_hash_opening() {
		let raw_key = [7u8; 32];
		let opening = BlockHash::opening(raw_key);
		assert_eq!(*opening.as_bytes(), hash_default(raw_key));
	}

	#[test]
	fn test_constants_and_compatibility() {
		// Verify constants match expected values
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
