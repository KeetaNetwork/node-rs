//! `keetanetwork-crypto` hash surface.

pub use keetanetwork_crypto::hash::HashAlgorithm;

/// Hash `data` with `algorithm`.
#[uniffi::export]
pub fn hash(algorithm: HashAlgorithm, data: Vec<u8>) -> Vec<u8> {
	algorithm.hash(data)
}

/// Canonical name of `algorithm` (e.g. `sha3-256`).
#[uniffi::export]
pub fn hash_algorithm_name(algorithm: HashAlgorithm) -> String {
	algorithm.name().into()
}

/// Digest length, in bytes, for `algorithm`.
#[uniffi::export]
pub fn hash_algorithm_length(algorithm: HashAlgorithm) -> u32 {
	algorithm.length() as u32
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hash_length_matches_declared_length() {
		let digest = hash(HashAlgorithm::Sha3_256, b"keeta".to_vec());
		assert_eq!(digest.len() as u32, hash_algorithm_length(HashAlgorithm::Sha3_256));
	}

	#[test]
	fn sha2_512_produces_sixty_four_bytes() {
		let digest = hash(HashAlgorithm::Sha2_512, Vec::new());
		assert_eq!(digest.len(), 64);
	}

	#[test]
	fn algorithm_names_are_canonical() {
		assert_eq!(hash_algorithm_name(HashAlgorithm::Sha3_256), "sha3-256");
		assert_eq!(hash_algorithm_name(HashAlgorithm::Sha2_256), "sha2-256");
		assert_eq!(hash_algorithm_name(HashAlgorithm::Sha2_512), "sha2-512");
	}
}
