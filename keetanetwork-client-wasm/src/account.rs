//! JS `Account`: a key pair or address usable as a signer or operand.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_bindings::account;
use keetanetwork_block::{AccountRef, BlockHash};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::convert::{coded, coded_error, parse_identifier_type, JsResult};

/// A KeetaNet account: a signing key pair when built from a seed or private
/// key, or a read-only handle when built from an address or public key.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Account {
	inner: AccountRef,
}

#[wasm_bindgen]
impl Account {
	/// Generate a fresh random 32-byte seed as hex. Persist it, then derive
	/// accounts from it with [`from_seed`](Self::from_seed).
	#[wasm_bindgen(js_name = generateSeed)]
	pub fn generate_seed() -> JsResult<String> {
		account::generate_seed().map_err(coded)
	}

	/// Generate a fresh BIP39 mnemonic. Persist the words, then derive accounts
	/// from them with [`from_passphrase`](Self::from_passphrase).
	#[wasm_bindgen(js_name = generatePassphrase)]
	pub fn generate_passphrase() -> JsResult<Vec<String>> {
		account::generate_passphrase().map_err(coded)
	}

	/// Derive an account from a 32-byte hex `seed` at derivation `index`.
	/// `algorithm` selects the signing key type; defaults to
	/// `"ecdsa_secp256k1"` when omitted.
	#[wasm_bindgen(js_name = fromSeed)]
	pub fn from_seed(seed: String, index: u32, algorithm: Option<String>) -> JsResult<Account> {
		let algorithm = algorithm.as_deref().unwrap_or(account::DEFAULT_ALGORITHM);
		account::account_from_seed(&seed, index, algorithm)
			.map(Account::from)
			.map_err(coded)
	}

	/// Build an account from a hex-encoded private `key`.
	#[wasm_bindgen(js_name = fromPrivateKey)]
	pub fn from_private_key(key: String, algorithm: String) -> JsResult<Account> {
		account::account_from_private_key(&key, &algorithm)
			.map(Account::from)
			.map_err(coded)
	}

	/// Derive an account from a BIP39 mnemonic `words` at derivation `index`.
	#[wasm_bindgen(js_name = fromPassphrase)]
	pub fn from_passphrase(words: Vec<String>, index: u32, algorithm: String) -> JsResult<Account> {
		account::account_from_passphrase(words, index, &algorithm)
			.map(Account::from)
			.map_err(coded)
	}

	/// Build a read-only account from a hex-encoded public `key`. Suitable as a
	/// recipient or token operand, but cannot sign.
	#[wasm_bindgen(js_name = fromPublicKey)]
	pub fn from_public_key(key: String, algorithm: String) -> JsResult<Account> {
		account::account_from_public_key(&key, &algorithm)
			.map(Account::from)
			.map_err(coded)
	}

	/// Build a read-only account from its textual `address`. Suitable as a
	/// recipient or token operand, but cannot sign.
	#[wasm_bindgen(js_name = fromAddress)]
	pub fn from_address(address: String) -> JsResult<Account> {
		account::account_from_address(&address)
			.map(Account::from)
			.map_err(coded)
	}

	/// The textual account address.
	#[wasm_bindgen(getter)]
	pub fn address(&self) -> String {
		account::account_address(&self.inner)
	}

	/// The signing algorithm name, or `"other"` for identifier accounts.
	#[wasm_bindgen(getter)]
	pub fn algorithm(&self) -> String {
		account::account_algorithm(&self.inner)
	}

	/// The type-prefixed public key transport bytes, hex-encoded.
	#[wasm_bindgen(getter, js_name = publicKey)]
	pub fn public_key(&self) -> String {
		account::account_public_key(&self.inner)
	}

	/// Derive an identifier account of `kind` relative to this account.
	#[wasm_bindgen(js_name = generateIdentifier)]
	pub fn generate_identifier(
		&self,
		kind: String,
		previous: Option<String>,
		op_index: Option<u32>,
	) -> JsResult<Account> {
		let kind = parse_identifier_type(&kind)?;
		let previous = previous
			.map(|hash| {
				BlockHash::from_str(&hash).map_err(|_| coded_error("INVALID_BLOCK_HASH", "block hash must be hex"))
			})
			.transpose()?;
		let identifier = self
			.inner
			.generate_identifier(kind, previous.as_ref(), op_index.unwrap_or(0))
			.map_err(|error| coded_error("IDENTIFIER", error.as_ref()))?;

		Ok(Self { inner: Arc::new(identifier) })
	}

	/// Sign `message`, returning the raw signature bytes. Errors when the
	/// account has no private key or its key type cannot sign.
	pub fn sign(&self, message: Vec<u8>) -> JsResult<Vec<u8>> {
		account::account_sign(&self.inner, &message).map_err(coded)
	}

	/// Whether `signature` is a valid signature of `message` by this account.
	pub fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
		account::account_verify(&self.inner, &message, &signature)
	}

	/// Encrypt `plaintext` to the account's public key. Errors when the key
	/// type does not support encryption.
	pub fn encrypt(&self, plaintext: Vec<u8>) -> JsResult<Vec<u8>> {
		account::account_encrypt(&self.inner, &plaintext).map_err(coded)
	}

	/// Decrypt `ciphertext` with the account's private key. Errors when the
	/// account has no private key or its key type does not support encryption.
	pub fn decrypt(&self, ciphertext: Vec<u8>) -> JsResult<Vec<u8>> {
		account::account_decrypt(&self.inner, &ciphertext).map_err(coded)
	}
}

impl Account {
	/// The wrapped account reference, cloned for delegation to the core client.
	pub(crate) fn inner(&self) -> AccountRef {
		Arc::clone(&self.inner)
	}
}

impl From<AccountRef> for Account {
	fn from(inner: AccountRef) -> Self {
		Self { inner }
	}
}
