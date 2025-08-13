//! Key Derivation Function (KDF) module for KeetaNet cryptographic operations.
//!
//! This module provides abstractions over different key derivation functions
//! used for expanding key material and deriving cryptographic keys.

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;

use crate::error::CryptoError;

/// Supported Key Derivation Functions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KdfAlgorithm {
	/// HKDF with SHA2-256 (RFC 5869)
	HkdfSha2_256,
	/// HKDF with SHA2-512 (RFC 5869)
	HkdfSha2_512,
	/// HKDF with SHA3-256 (FIPS 202)
	HkdfSha3_256,
}

impl KdfAlgorithm {
	/// Get the algorithm name as a string
	pub fn name(&self) -> &'static str {
		match self {
			KdfAlgorithm::HkdfSha2_256 => "hkdf-sha2-256",
			KdfAlgorithm::HkdfSha2_512 => "hkdf-sha2-512",
			KdfAlgorithm::HkdfSha3_256 => "hkdf-sha3-256",
		}
	}

	/// Get the maximum output length in bytes for this KDF
	pub fn max_output_length(&self) -> usize {
		match self {
			KdfAlgorithm::HkdfSha2_256 => 255 * 32, // 255 * hash_len for HKDF
			KdfAlgorithm::HkdfSha2_512 => 255 * 64, // 255 * hash_len for HKDF
			KdfAlgorithm::HkdfSha3_256 => 255 * 32, // 255 * hash_len for HKDF
		}
	}

	/// Derive key material using this KDF algorithm
	///
	/// # Arguments
	/// * `ikm` - Input Key Material (the source key material)
	/// * `salt` - Optional salt (None for no salt)
	/// * `info` - Context/application-specific info
	/// * `output_length` - Desired output length in bytes
	///
	/// # Returns
	/// Derived key material of the specified length
	pub fn derive(
		&self,
		ikm: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		info: impl AsRef<[u8]>,
		output_length: usize,
	) -> Result<Vec<u8>, CryptoError> {
		let ikm = ikm.as_ref();
		let info = info.as_ref();

		if output_length > self.max_output_length() {
			return Err(CryptoError::InvalidLength);
		}

		match self {
			KdfAlgorithm::HkdfSha2_256 => {
				let hk = Hkdf::<Sha256>::new(salt, ikm);
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
			KdfAlgorithm::HkdfSha2_512 => {
				let hk = Hkdf::<Sha512>::new(salt, ikm);
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
			KdfAlgorithm::HkdfSha3_256 => {
				let hk = Hkdf::<Sha3_256>::new(salt, ikm);
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
		}
	}

	/// Derive key material using expand-only (treating IKM as PRK).
	///
	/// This method treats the input key material as already-extracted PRK
	/// and performs only the expand step. This is used for node TypeScript
	/// compatibility where the seed is treated directly as PRK material.
	///
	/// # Arguments
	/// * `prk` - Pre-extracted key material (treated as PRK)
	/// * `info` - Context/application-specific info
	/// * `output_length` - Desired output length in bytes
	///
	/// # Returns
	/// Derived key material of the specified length
	pub fn expand_only(
		&self,
		prk: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
		output_length: usize,
	) -> Result<Vec<u8>, CryptoError> {
		let prk = prk.as_ref();
		let info = info.as_ref();

		if output_length > self.max_output_length() {
			return Err(CryptoError::InvalidLength);
		}

		match self {
			KdfAlgorithm::HkdfSha2_256 => {
				let hk = Hkdf::<Sha256>::from_prk(prk)?;
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
			KdfAlgorithm::HkdfSha2_512 => {
				let hk = Hkdf::<Sha512>::from_prk(prk)?;
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
			KdfAlgorithm::HkdfSha3_256 => {
				let hk = Hkdf::<Sha3_256>::from_prk(prk)?;
				let mut okm = vec![0u8; output_length];

				hk.expand(info, &mut okm)?;
				Ok(okm)
			}
		}
	}

	/// Derive key material as a fixed-size array.
	///
	/// # Arguments
	/// * `ikm` - Input Key Material
	/// * `salt` - Optional salt
	/// * `info` - Context/application-specific info
	///
	/// # Returns
	/// Derived key material as a fixed-size array
	pub fn derive_array<const N: usize>(
		&self,
		ikm: impl AsRef<[u8]>,
		salt: Option<&[u8]>,
		info: impl AsRef<[u8]>,
	) -> Result<[u8; N], CryptoError> {
		let okm = self.derive(ikm, salt, info, N)?;
		let mut array = [0u8; N];

		array.copy_from_slice(&okm);
		Ok(array)
	}

	/// Expand-only derivation as a fixed-size array.
	///
	/// # Arguments
	/// * `prk` - Pre-extracted key material
	/// * `info` - Context/application-specific info
	///
	/// # Returns
	/// Derived key material as a fixed-size array
	pub fn expand_only_array<const N: usize>(
		&self,
		prk: impl AsRef<[u8]>,
		info: impl AsRef<[u8]>,
	) -> Result<[u8; N], CryptoError> {
		let okm = self.expand_only(prk, info, N)?;
		let mut array = [0u8; N];

		array.copy_from_slice(&okm);
		Ok(array)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const ALL_ALGORITHMS: [KdfAlgorithm; 3] =
		[KdfAlgorithm::HkdfSha2_256, KdfAlgorithm::HkdfSha2_512, KdfAlgorithm::HkdfSha3_256];

	#[test]
	fn test_kdf_algorithm_properties() {
		let algorithms = ALL_ALGORITHMS;
		for algo in algorithms {
			// Test basic properties
			assert!(!algo.name().is_empty());
			assert!(algo.max_output_length() > 0);

			// Test that different algorithms have different names
			for other in algorithms {
				if algo != other {
					assert_ne!(algo.name(), other.name());
				}
			}
		}
	}

	#[test]
	fn test_hkdf_derivation() {
		let ikm = b"test input key material";
		let salt = Some(b"optional salt".as_slice());
		let info = b"application info";

		for algo in ALL_ALGORITHMS {
			// Test various output lengths
			for &length in &[16, 32, 48, 64] {
				let okm = algo.derive(ikm, salt, info, length).unwrap();
				assert_eq!(okm.len(), length);

				// Test that longer derivations contain the shorter ones as prefixes
				if length > 16 {
					let shorter = algo.derive(ikm, salt, info, 16).unwrap();
					assert_eq!(okm[..16], shorter[..]);
				}
			}

			// Test with no salt
			let no_salt = algo.derive(ikm, None, info, 32).unwrap();
			let with_salt = algo.derive(ikm, salt, info, 32).unwrap();
			assert_ne!(no_salt, with_salt);

			// Test with different info
			let info1 = algo.derive(ikm, salt, b"info1", 32).unwrap();
			let info2 = algo.derive(ikm, salt, b"info2", 32).unwrap();
			assert_ne!(info1, info2);

			// Test with different IKM
			let ikm1 = algo.derive(b"ikm1", salt, info, 32).unwrap();
			let ikm2 = algo.derive(b"ikm2", salt, info, 32).unwrap();
			assert_ne!(ikm1, ikm2);
		}
	}

	#[test]
	fn test_hkdf_array_derivation() {
		let ikm = b"test input key material";
		let salt = Some(b"salt".as_slice());
		let info = b"info";

		for algo in ALL_ALGORITHMS {
			// Test fixed-size array derivation
			let array: [u8; 32] = algo.derive_array(ikm, salt, info).unwrap();
			let vec_result = algo.derive(ikm, salt, info, 32).unwrap();
			assert_eq!(array.to_vec(), vec_result);

			// Test different array sizes - they should have consistent prefixes
			let array16: [u8; 16] = algo.derive_array(ikm, salt, info).unwrap();
			let array64: [u8; 64] = algo.derive_array(ikm, salt, info).unwrap();
			// HKDF produces consistent prefixes
			assert_eq!(array16[..], array[..16]);
			assert_eq!(array[..], array64[..32]);

			// But different salt/info should produce different results
			let array_diff_salt: [u8; 32] = algo.derive_array(ikm, None, info).unwrap();
			let array_diff_info: [u8; 32] = algo.derive_array(ikm, salt, b"different").unwrap();
			assert_ne!(array, array_diff_salt);
			assert_ne!(array, array_diff_info);
		}
	}

	#[test]
	fn test_deterministic_derivation() {
		let ikm = b"test input key material";
		let salt = Some(b"salt".as_slice());
		let info = b"info";

		for algo in ALL_ALGORITHMS {
			// Multiple calls should produce identical results
			let result1 = algo.derive(ikm, salt, info, 32).unwrap();
			let result2 = algo.derive(ikm, salt, info, 32).unwrap();
			let result3 = algo.derive(ikm, salt, info, 32).unwrap();
			assert_eq!(result1, result2);
			assert_eq!(result2, result3);
		}
	}

	#[test]
	fn test_error_conditions() {
		let ikm = b"test";
		let algo = KdfAlgorithm::HkdfSha2_256;

		// Test invalid output length
		let max_len = algo.max_output_length();
		let invalid_result = algo.derive(ikm, None, b"", max_len + 1);
		assert_eq!(invalid_result.unwrap_err(), CryptoError::InvalidLength);

		// Test zero-length output (should work)
		let zero_result = algo.derive(ikm, None, b"", 0).unwrap();
		assert!(zero_result.is_empty());
	}

	#[test]
	fn test_algorithm_differences() {
		let ikm = b"test input key material";
		let salt = Some(b"salt".as_slice());
		let info = b"info";

		// Different algorithms should produce different results
		let sha256_result = KdfAlgorithm::HkdfSha2_256
			.derive(ikm, salt, info, 32)
			.unwrap();
		let sha512_result = KdfAlgorithm::HkdfSha2_512
			.derive(ikm, salt, info, 32)
			.unwrap();
		assert_ne!(sha256_result, sha512_result);
	}

	#[test]
	fn test_ecies_compatibility() {
		// Test the exact pattern used in ECIES
		let ephemeral_pk = hex::decode("04abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890").unwrap();
		let shared_secret = hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12").unwrap();

		// Combine like ECIES does
		let mut combined = Vec::with_capacity(ephemeral_pk.len() + shared_secret.len());
		combined.extend_from_slice(&ephemeral_pk);
		combined.extend_from_slice(&shared_secret);

		// Derive key using our KDF
		let derived_key = KdfAlgorithm::HkdfSha2_256
			.derive_array::<32>(&combined, None, b"")
			.unwrap();
		// Should be deterministic - test with the generic derive function
		let derived_key2 = KdfAlgorithm::HkdfSha2_256
			.derive(&combined, None, b"", 32)
			.unwrap();
		assert_eq!(derived_key.to_vec(), derived_key2);
		assert_eq!(derived_key.len(), 32);
	}
}
