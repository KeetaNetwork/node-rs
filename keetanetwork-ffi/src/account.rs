//! `keetanetwork-account` surface.

pub use keetanetwork_account::KeyPairType;

/// Whether `key_type` denotes an identifier account.
#[uniffi::export]
pub fn key_pair_type_is_identifier(key_type: KeyPairType) -> bool {
	key_type.is_identifier()
}

/// Whether `key_type` supports cryptographic signing.
#[uniffi::export]
pub fn key_pair_type_supports_crypto(key_type: KeyPairType) -> bool {
	key_type.supports_crypto()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn identifier_types_are_not_crypto() {
		assert!(key_pair_type_is_identifier(KeyPairType::MULTISIG));
		assert!(!key_pair_type_supports_crypto(KeyPairType::MULTISIG));
	}

	#[test]
	fn keyed_types_support_crypto() {
		assert!(key_pair_type_supports_crypto(KeyPairType::ED25519));
		assert!(!key_pair_type_is_identifier(KeyPairType::ED25519));
	}
}
