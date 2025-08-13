/*
 * Import the necessary modules and re-export them for use in the main module.
 */

pub mod account;
pub mod constants;
pub mod error;
pub mod utils;

// Re-export the main types for easier use
pub use account::{
	Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyMULTISIG, KeyNETWORK,
	KeyPair, KeyPairType, KeySTORAGE, KeyTOKEN, Keyable,
};
pub use error::AccountError;

use secrecy::SecretBox;
use zeroize::Zeroize;

/// A 256-bit seed used for key derivation.
pub type Seed = SecretBox<[u8; 32]>;
/// A hex-encoded seed used for key derivation, stored securely.
pub type HexSeed = SecretBox<String>;
/// A passphrase used for key derivation, stored securely.
pub type Passphrase = SecretBox<Vec<String>>;

/// Trait for converting types into their corresponding SecretBox versions.
pub trait IntoSecret<T: Zeroize> {
	/// Convert the value into a SecretBox.
	fn into_secret(self) -> SecretBox<T>;
}

impl IntoSecret<[u8; 32]> for [u8; 32] {
	fn into_secret(self) -> Seed {
		SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<String> for String {
	fn into_secret(self) -> HexSeed {
		SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<Vec<String>> for Vec<String> {
	fn into_secret(self) -> Passphrase {
		SecretBox::new(Box::new(self))
	}
}

/// An index used to derive keys from a seed.
pub type Index = u32;

/// Type alias for a passphrase and its derivation index.
pub type PassphraseAndIndex = (Passphrase, Index);
/// Type alias for a hex-encoded seed and its derivation index.
pub type HexSeedAndIndex = (HexSeed, Index);
/// Type alias for a seed and its derivation index.
pub type SeedAndIndex = (Seed, Index);

#[cfg(test)]
mod tests {
	use super::*;
	use secrecy::ExposeSecret;

	#[test]
	fn test_into_secret_for_seed() {
		let seed_array = [1u8; 32];
		let seed: Seed = seed_array.into_secret();
		assert_eq!(*seed.expose_secret(), seed_array);
	}

	#[test]
	fn test_into_secret_for_hex_seed() {
		let hex_string = "deadbeef".to_string();
		let hex_seed: HexSeed = hex_string.clone().into_secret();
		assert_eq!(*hex_seed.expose_secret(), hex_string);
	}

	#[test]
	fn test_into_secret_for_passphrase() {
		let passphrase_vec = vec!["word1".to_string(), "word2".to_string()];
		let passphrase: Passphrase = passphrase_vec.clone().into_secret();
		assert_eq!(*passphrase.expose_secret(), passphrase_vec);
	}
}
