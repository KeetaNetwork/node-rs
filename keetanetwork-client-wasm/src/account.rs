//! JS `Account`: a key pair or address usable as a signer or operand.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::{Account as CoreAccount, GenericAccount, KeyED25519, Keyable};
use keetanetwork_block::{AccountRef, BlockHash};
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret};
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
		let seed =
			CoreAccount::<KeyED25519>::generate_random_seed().map_err(|error| coded_error("RNG", error.as_ref()))?;
		Ok(hex::encode(seed.expose_secret()))
	}

	/// Generate a fresh BIP39 mnemonic. Persist the words, then derive accounts
	/// from them with [`from_passphrase`](Self::from_passphrase).
	#[wasm_bindgen(js_name = generatePassphrase)]
	pub fn generate_passphrase() -> JsResult<Vec<String>> {
		let passphrase =
			CoreAccount::<KeyED25519>::generate_passphrase().map_err(|error| coded_error("RNG", error.as_ref()))?;
		Ok(passphrase.expose_secret().clone())
	}

	/// Derive an account from a 32-byte hex `seed` at derivation `index`.
	/// `algorithm` selects the signing key type; defaults to
	/// `"ecdsa_secp256k1"` when omitted.
	#[wasm_bindgen(js_name = fromSeed)]
	pub fn from_seed(seed: String, index: u32, algorithm: Option<String>) -> JsResult<Account> {
		let mut bytes = [0u8; 32];
		hex::decode_to_slice(&seed, &mut bytes).map_err(|_| coded_error("INVALID_SEED", "seed must be 32-byte hex"))?;

		let algorithm = algorithm.as_deref().unwrap_or("ecdsa_secp256k1");
		Self::from_keyable(Keyable::Seed((bytes.into_secret(), index)), algorithm)
	}

	/// Build an account from a hex-encoded private `key`.
	#[wasm_bindgen(js_name = fromPrivateKey)]
	pub fn from_private_key(key: String, algorithm: String) -> JsResult<Account> {
		let bytes = hex::decode(&key).map_err(|_| coded_error("INVALID_PRIVATE_KEY", "private key must be hex"))?;
		Self::from_keyable(Keyable::PrivateKey(bytes), &algorithm)
	}

	/// Derive an account from a BIP39 mnemonic `words` at derivation `index`.
	#[wasm_bindgen(js_name = fromPassphrase)]
	pub fn from_passphrase(words: Vec<String>, index: u32, algorithm: String) -> JsResult<Account> {
		Self::from_keyable(Keyable::from((words, index)), &algorithm)
	}

	/// Build a read-only account from a hex-encoded public `key`. Suitable as a
	/// recipient or token operand, but cannot sign.
	#[wasm_bindgen(js_name = fromPublicKey)]
	pub fn from_public_key(key: String, algorithm: String) -> JsResult<Account> {
		let bytes = hex::decode(&key).map_err(|_| coded_error("INVALID_PUBLIC_KEY", "public key must be hex"))?;
		Self::from_keyable(Keyable::PublicKey(bytes), &algorithm)
	}

	/// Build a read-only account from its textual `address`. Suitable as a
	/// recipient or token operand, but cannot sign.
	#[wasm_bindgen(js_name = fromAddress)]
	pub fn from_address(address: String) -> JsResult<Account> {
		let account = GenericAccount::from_str(&address)
			.map_err(|_| coded_error("INVALID_ADDRESS", "invalid account address"))?;
		Ok(Self { inner: Arc::new(account) })
	}

	/// The textual account address.
	#[wasm_bindgen(getter)]
	pub fn address(&self) -> String {
		self.inner.to_string()
	}

	/// The signing algorithm name, or `"other"` for identifier accounts.
	#[wasm_bindgen(getter)]
	pub fn algorithm(&self) -> String {
		String::from(keetanetwork_bindings::account::algorithm_name(self.inner.to_keypair_type()))
	}

	/// The type-prefixed public key transport bytes, hex-encoded.
	#[wasm_bindgen(getter, js_name = publicKey)]
	pub fn public_key(&self) -> String {
		hex::encode(self.inner.to_public_key_with_type())
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
		AccountSigner::sign(self.inner.as_ref(), message, None).map_err(|error| coded_error("SIGN", error.as_ref()))
	}

	/// Whether `signature` is a valid signature of `message` by this account.
	pub fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
		self.inner.verify(message, signature, None).is_ok()
	}

	/// Encrypt `plaintext` to the account's public key. Errors when the key
	/// type does not support encryption.
	pub fn encrypt(&self, plaintext: Vec<u8>) -> JsResult<Vec<u8>> {
		self.inner
			.encrypt(plaintext)
			.map_err(|error| coded_error("ENCRYPT", error.as_ref()))
	}

	/// Decrypt `ciphertext` with the account's private key. Errors when the
	/// account has no private key or its key type does not support encryption.
	pub fn decrypt(&self, ciphertext: Vec<u8>) -> JsResult<Vec<u8>> {
		self.inner
			.decrypt(ciphertext)
			.map_err(|error| coded_error("DECRYPT", error.as_ref()))
	}
}

impl Account {
	/// The wrapped account reference, cloned for delegation to the core client.
	pub(crate) fn inner(&self) -> AccountRef {
		Arc::clone(&self.inner)
	}

	fn from_keyable(keyable: Keyable, algorithm: &str) -> JsResult<Account> {
		let account = keetanetwork_bindings::account::from_keyable(keyable, algorithm).map_err(coded)?;
		Ok(Self { inner: Arc::new(account) })
	}
}

impl From<AccountRef> for Account {
	fn from(inner: AccountRef) -> Self {
		Self { inner }
	}
}
