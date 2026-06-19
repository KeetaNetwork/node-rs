//! Certificate-mode signing and verification helpers.
//!
//! Certificate mode is the message-handling convention used by Keeta vote
//! certificates and other X.509-shaped artifacts:
//!
//! * **ECDSA** - the message is pre-hashed with the network's default hash
//!   algorithm (SHA3-256) and the resulting digest is signed; signatures are
//!   serialized as ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }`.
//! * **Ed25519** - the message is signed directly (Ed25519 already hashes
//!   internally); signatures are the standard 64-byte raw form.
//!
//! These traits hide the algorithm-specific framing so a caller working with
//! a [`GenericAccount`] does not need to branch on key type. Identifier
//! accounts cannot sign or verify certificates and return
//! [`AccountError::NoIdentifierSign`] / [`AccountError::NoIdentifierVerify`].

use alloc::vec::Vec;

use keetanetwork_crypto::algorithms::ed25519::Ed25519Signature;
use keetanetwork_crypto::algorithms::secp256k1::Secp256k1Signature;
use keetanetwork_crypto::algorithms::secp256r1::Secp256r1Signature;
use keetanetwork_crypto::hash::hash_default;
use keetanetwork_crypto::operations::signature::{CryptoSignerWithOptions, CryptoVerifierWithOptions, SigningOptions};

use crate::account::{Account, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519};
use crate::error::AccountError;

/// Sign messages using the certificate-mode convention.
///
/// The wire output format is algorithm-specific; see the [module
/// documentation](self) for details.
pub trait CertSigner {
	/// Sign `message` for embedding in an X.509-shaped certificate.
	fn sign_for_cert(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, AccountError>;
}

/// Verify certificate-mode signatures.
pub trait CertVerifier {
	/// Verify `signature` over `message` produced by [`CertSigner::sign_for_cert`].
	fn verify_for_cert(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), AccountError>;
}

fn ecdsa_prehash(message: &[u8]) -> [u8; 32] {
	hash_default(message)
}

impl CertSigner for Account<KeyECDSASECP256K1> {
	fn sign_for_cert(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, AccountError> {
		let prehash = ecdsa_prehash(message.as_ref());
		let signature: Secp256k1Signature = self
			.keypair
			.sign_with_options(prehash, SigningOptions::raw())?;
		Ok(signature.to_der().as_bytes().to_vec())
	}
}

impl CertSigner for Account<KeyECDSASECP256R1> {
	fn sign_for_cert(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, AccountError> {
		let prehash = ecdsa_prehash(message.as_ref());
		let signature: Secp256r1Signature = self
			.keypair
			.sign_with_options(prehash, SigningOptions::raw())?;
		Ok(signature.to_der().as_bytes().to_vec())
	}
}

impl CertSigner for Account<KeyED25519> {
	fn sign_for_cert(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, AccountError> {
		// Equivalent to the TS reference implementation: ed25519 certificate signatures
		// are produced by signing the raw TBS bytes (no pre-hash) and emitted
		// as the standard 64-byte raw form.
		let signature: Ed25519Signature = self
			.keypair
			.sign_with_options(message, SigningOptions::raw())?;
		Ok(signature.to_bytes().to_vec())
	}
}

impl CertVerifier for Account<KeyECDSASECP256K1> {
	fn verify_for_cert(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), AccountError> {
		let prehash = ecdsa_prehash(message.as_ref());
		let parsed = Secp256k1Signature::from_der(signature.as_ref()).map_err(|_| AccountError::InvalidConstruction)?;
		Ok(self
			.keypair
			.verify_with_options(prehash, &parsed, SigningOptions::raw())?)
	}
}

impl CertVerifier for Account<KeyECDSASECP256R1> {
	fn verify_for_cert(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), AccountError> {
		let prehash = ecdsa_prehash(message.as_ref());
		let parsed = Secp256r1Signature::from_der(signature.as_ref()).map_err(|_| AccountError::InvalidConstruction)?;
		Ok(self
			.keypair
			.verify_with_options(prehash, &parsed, SigningOptions::raw())?)
	}
}

impl CertVerifier for Account<KeyED25519> {
	fn verify_for_cert(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), AccountError> {
		let parsed = Ed25519Signature::try_from(signature.as_ref())?;
		Ok(self
			.keypair
			.verify_with_options(message, &parsed, SigningOptions::raw())?)
	}
}

impl CertSigner for GenericAccount {
	fn sign_for_cert(&self, message: impl AsRef<[u8]>) -> Result<Vec<u8>, AccountError> {
		match self {
			GenericAccount::EcdsaSecp256k1(account) => account.sign_for_cert(message),
			GenericAccount::EcdsaSecp256r1(account) => account.sign_for_cert(message),
			GenericAccount::Ed25519(account) => account.sign_for_cert(message),
			_ => Err(AccountError::NoIdentifierSign),
		}
	}
}

impl CertVerifier for GenericAccount {
	fn verify_for_cert(&self, message: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), AccountError> {
		match self {
			GenericAccount::EcdsaSecp256k1(account) => account.verify_for_cert(message, signature),
			GenericAccount::EcdsaSecp256r1(account) => account.verify_for_cert(message, signature),
			GenericAccount::Ed25519(account) => account.verify_for_cert(message, signature),
			_ => Err(AccountError::NoIdentifierVerify),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::account::{Account, GenericAccount, KeyECDSASECP256K1, KeyECDSASECP256R1, KeyED25519, KeyPairType};
	use crate::doc_utils::{create_ed25519_test_keys, create_secp256k1_test_keys, create_secp256r1_test_keys};

	fn secp256k1_account() -> Account<KeyECDSASECP256K1> {
		let (_, _, account) = create_secp256k1_test_keys(Some(&[11u8; 64]));
		account
	}

	fn secp256r1_account() -> Account<KeyECDSASECP256R1> {
		let (_, _, account) = create_secp256r1_test_keys(Some(&[22u8; 64]));
		account
	}

	fn ed25519_account_with_seed(seed: &[u8]) -> Account<KeyED25519> {
		let mut padded = vec![0u8; 64];
		padded[..seed.len().min(64)].copy_from_slice(&seed[..seed.len().min(64)]);
		let (_, _, account) = create_ed25519_test_keys(Some(&padded));
		account
	}

	#[test]
	fn test_secp256k1_round_trip() -> Result<(), AccountError> {
		let account = secp256k1_account();
		let signature = account.sign_for_cert(b"hello world")?;
		account.verify_for_cert(b"hello world", &signature)
	}

	#[test]
	fn test_secp256r1_round_trip() -> Result<(), AccountError> {
		let account = secp256r1_account();
		let signature = account.sign_for_cert(b"hello world")?;
		account.verify_for_cert(b"hello world", &signature)
	}

	#[test]
	fn test_ed25519_round_trip() -> Result<(), AccountError> {
		let account = ed25519_account_with_seed(b"alice");
		let signature = account.sign_for_cert(b"hello world")?;
		account.verify_for_cert(b"hello world", &signature)
	}

	#[test]
	fn test_ed25519_signature_is_64_bytes() -> Result<(), AccountError> {
		let signature = ed25519_account_with_seed(b"alice").sign_for_cert(b"abc")?;
		assert_eq!(signature.len(), 64);
		Ok(())
	}

	#[test]
	fn test_secp256k1_signature_is_der() -> Result<(), AccountError> {
		let signature = secp256k1_account().sign_for_cert(b"abc")?;
		// A DER `SEQUENCE` always begins with 0x30.
		assert_eq!(signature.first().copied(), Some(0x30));
		Ok(())
	}

	#[test]
	fn test_round_trip_via_generic_account() -> Result<(), AccountError> {
		let account = GenericAccount::Ed25519(ed25519_account_with_seed(b"alice"));
		let signature = account.sign_for_cert(b"hello")?;
		account.verify_for_cert(b"hello", &signature)
	}

	#[test]
	fn test_identifier_account_cannot_sign() -> Result<(), AccountError> {
		let signer = ed25519_account_with_seed(b"alice");
		let storage = signer.generate_identifier(KeyPairType::STORAGE, None, 0)?;
		assert!(matches!(storage.sign_for_cert(b"x"), Err(AccountError::NoIdentifierSign)));
		assert!(matches!(storage.verify_for_cert(b"x", b"y"), Err(AccountError::NoIdentifierVerify)));
		Ok(())
	}

	#[test]
	fn test_signature_from_other_account_rejected() -> Result<(), AccountError> {
		let alice = ed25519_account_with_seed(b"alice");
		let bob = ed25519_account_with_seed(b"bob");
		let signature = alice.sign_for_cert(b"abc")?;
		assert!(bob.verify_for_cert(b"abc", &signature).is_err());
		Ok(())
	}
}
