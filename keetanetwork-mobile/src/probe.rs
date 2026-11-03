//! Compares this library with the web wallet vectors on the target device.
//!
//! The vectors hold test-only phrases and stay inside the library.

use keetanetwork_crypto::prelude::SigningOptions;
use serde_json::Value;

use crate::{phrase_from_entropy, verify, Wallet, WalletError};

const WEB_VECTORS: &str = include_str!("../tests/fixtures/web-vectors.json");

fn text(value: &Value) -> Result<&str, WalletError> {
	value.as_str().ok_or(WalletError::InvalidEntropy)
}

fn bytes(value: &Value) -> Result<Vec<u8>, WalletError> {
	hex::decode(text(value)?).map_err(|_| WalletError::InvalidEntropy)
}

/// Returns the number of accounts checked. Each mismatch returns the error of its operation.
#[uniffi::export]
pub fn run_web_vector_probe() -> Result<u32, WalletError> {
	let fixture: Value = serde_json::from_str(WEB_VECTORS).map_err(|_| WalletError::InvalidEntropy)?;
	let message = bytes(&fixture["message"])?;
	let digest = SigningOptions::default()
		.digest(&message)
		.map_err(|_| WalletError::Sign)?;
	let vectors = fixture["vectors"]
		.as_array()
		.ok_or(WalletError::InvalidEntropy)?;
	let mut checked = 0;
	for vector in vectors {
		let phrase = text(&vector["phrase"])?;
		if phrase_from_entropy(&bytes(&vector["entropy"])?)?.as_str() != phrase {
			return Err(WalletError::InvalidPhrase);
		}
		let wallet = Wallet::from_phrase(phrase)?;
		let accounts = vector["accounts"]
			.as_array()
			.ok_or(WalletError::InvalidEntropy)?;
		for account in accounts {
			let index = account["index"]
				.as_u64()
				.and_then(|index| u32::try_from(index).ok())
				.ok_or(WalletError::InvalidEntropy)?;
			let public_key = text(&account["publicKey"])?;
			if wallet.public_key(index)? != public_key {
				return Err(WalletError::Derivation);
			}
			let signature = bytes(&account["signature"])?;
			if wallet.sign(index, &message)? != signature
				|| wallet.sign_digest(index, &digest)? != signature
				|| !verify(public_key, &message, &signature)?
			{
				return Err(WalletError::Sign);
			}
			if wallet.decrypt(index, &bytes(&account["ciphertext"])?)? != message {
				return Err(WalletError::Decrypt);
			}
			checked += 1;
		}
	}
	Ok(checked)
}
