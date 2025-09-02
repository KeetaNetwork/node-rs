//! Cryptographic primitives for KeetaNet node
//!
//! This crate provides algorithm-agnostic cryptographic operations including:
//! - Key generation and derivation
//! - Public key formatting with checksums
//! - Support for multiple algorithms (secp256k1, Ed25519)

pub mod algorithms;
pub mod bigint;
pub mod constants;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod operations;
pub mod prelude;
pub mod utils;

// Testing
#[cfg(test)]
pub mod test_utils;

/// Trait for converting types into their corresponding SecretBox versions.
pub trait IntoSecret<T: zeroize::Zeroize> {
	/// Convert the value into a SecretBox.
	fn into_secret(self) -> secrecy::SecretBox<T>;
}

impl<T: zeroize::Zeroize> IntoSecret<Vec<T>> for Vec<T> {
	fn into_secret(self) -> secrecy::SecretBox<Vec<T>> {
		secrecy::SecretBox::new(Box::new(self))
	}
}

impl<const N: usize> IntoSecret<[u8; N]> for [u8; N] {
	fn into_secret(self) -> secrecy::SecretBox<[u8; N]> {
		secrecy::SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<String> for String {
	fn into_secret(self) -> secrecy::SecretBox<String> {
		secrecy::SecretBox::new(Box::new(self))
	}
}

impl IntoSecret<String> for &str {
	fn into_secret(self) -> secrecy::SecretBox<String> {
		secrecy::SecretBox::new(Box::new(self.to_string()))
	}
}

impl IntoSecret<Vec<String>> for &[&str] {
	fn into_secret(self) -> secrecy::SecretBox<Vec<String>> {
		secrecy::SecretBox::new(Box::new(self.iter().map(|s| s.to_string()).collect()))
	}
}

impl IntoSecret<Vec<String>> for Vec<&str> {
	fn into_secret(self) -> secrecy::SecretBox<Vec<String>> {
		self.as_slice().into_secret()
	}
}

#[cfg(test)]
mod tests {
	use secrecy::{ExposeSecret, SecretBox};

	use super::*;

	#[test]
	fn test_into_secret_implementations() {
		// Macro to test IntoSecret implementations
		macro_rules! test_into_secret {
			($test_name:ident, $input:expr, $secret_type:ty) => {
				let input = $input;
				let secret: SecretBox<$secret_type> = input.clone().into_secret();
				assert_eq!(*secret.expose_secret(), input);
			};
		}

		// Test data-driven cases
		test_into_secret!(seed, [1u8; 32], [u8; 32]);
		test_into_secret!(hex_seed, "deadbeef".to_string(), String);
		test_into_secret!(passphrase, vec!["word1".to_string(), "word2".to_string()], Vec<String>);

		// Test &str
		let secret = "deadbeef".into_secret();
		assert_eq!(*secret.expose_secret(), "deadbeef".to_string());

		// Test Vec<&str>
		let secret = vec!["word1", "word2"].into_secret();
		assert_eq!(*secret.expose_secret(), vec!["word1".to_string(), "word2".to_string()]);

		// Test &[&str]
		let secret = &["word1", "word2"].into_secret();
		assert_eq!(*secret.expose_secret(), vec!["word1".to_string(), "word2".to_string()]);
	}
}
