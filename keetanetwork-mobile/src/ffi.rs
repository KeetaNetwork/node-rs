//! UniFFI surface for the Swift and Kotlin layer.
//!
//! Phrases cross as bytes, because a host can overwrite a byte buffer but
//! cannot overwrite a Swift or Kotlin string.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::{generate_phrase, phrase_from_entropy, phrase_status, verify, PhraseStatus, Wallet, WalletError};

fn phrase_text(phrase: &[u8]) -> Result<&str, WalletError> {
	std::str::from_utf8(phrase).map_err(|_| WalletError::InvalidPhrase)
}

#[uniffi::export]
pub fn generate_phrase_bytes() -> Result<Vec<u8>, WalletError> {
	Ok(generate_phrase()?.as_bytes().to_vec())
}

#[uniffi::export]
pub fn phrase_bytes_from_entropy(entropy: Vec<u8>) -> Result<Vec<u8>, WalletError> {
	let entropy = Zeroizing::new(entropy);
	Ok(phrase_from_entropy(&entropy)?.as_bytes().to_vec())
}

#[uniffi::export]
pub fn verify_signature(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> Result<bool, WalletError> {
	verify(&public_key, &message, &signature)
}

#[uniffi::export]
pub fn phrase_status_bytes(phrase: Vec<u8>) -> Result<PhraseStatus, WalletError> {
	let phrase = Zeroizing::new(phrase);
	Ok(phrase_status(phrase_text(&phrase)?))
}

#[derive(uniffi::Object)]
pub struct MobileWallet {
	wallet: Wallet,
}

#[uniffi::export]
impl MobileWallet {
	#[uniffi::constructor]
	pub fn from_phrase_bytes(phrase: Vec<u8>) -> Result<Arc<Self>, WalletError> {
		let phrase = Zeroizing::new(phrase);
		let wallet = Wallet::from_phrase(phrase_text(&phrase)?)?;
		Ok(Arc::new(Self { wallet }))
	}

	#[uniffi::constructor]
	pub fn from_unverified_phrase_bytes(phrase: Vec<u8>) -> Result<Arc<Self>, WalletError> {
		let phrase = Zeroizing::new(phrase);
		let wallet = Wallet::from_unverified_phrase(phrase_text(&phrase)?)?;
		Ok(Arc::new(Self { wallet }))
	}

	pub fn public_key(&self, index: u32) -> Result<String, WalletError> {
		self.wallet.public_key(index)
	}

	pub fn sign(&self, index: u32, message: Vec<u8>) -> Result<Vec<u8>, WalletError> {
		self.wallet.sign(index, &message)
	}

	pub fn sign_digest(&self, index: u32, digest: Vec<u8>) -> Result<Vec<u8>, WalletError> {
		self.wallet.sign_digest(index, &digest)
	}

	pub fn decrypt(&self, index: u32, ciphertext: Vec<u8>) -> Result<Vec<u8>, WalletError> {
		self.wallet.decrypt(index, &ciphertext)
	}
}
