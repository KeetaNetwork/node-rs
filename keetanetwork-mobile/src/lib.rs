//! Wallet key operations for the KeetaNet mobile native module.
//!
//! The secret stays in [`Wallet`]. A host receives only public keys,
//! signatures and plaintext it asked to decrypt.

use bip39_dict::{Entropy, Language, Mnemonics, ENGLISH};
use keetanetwork_account::account::AccountSigner;
use keetanetwork_account::{Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyPairType, Keyable};
use keetanetwork_bindings::account::{
	account_decrypt, account_encrypt, account_from_public_key_string, account_public_key_string, account_sign,
	account_verify,
};
use keetanetwork_block::AccountRef;
use keetanetwork_crypto::prelude::{ExposeSecret, IntoSecret, SigningOptions};
use keetanetwork_crypto::utils::{generate_random_bytes, seed_from_passphrase};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

const ENTROPY_BYTES: usize = 32;
const PHRASE_WORDS: usize = 24;
const CHECKSUM_BITS: usize = 8;

mod allocator;
pub mod ffi;

uniffi::setup_scaffolding!();

#[global_allocator]
static ALLOCATOR: allocator::ZeroizingAllocator = allocator::ZeroizingAllocator;

#[derive(Debug, PartialEq, Eq, uniffi::Error)]
pub enum WalletError {
	InvalidEntropy,
	InvalidPhrase,
	InvalidPublicKey,
	Random,
	Derivation,
	Sign,
	Encrypt,
	Decrypt,
}

impl std::fmt::Display for WalletError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		std::fmt::Debug::fmt(self, formatter)
	}
}

impl std::error::Error for WalletError {}

/// Generate a 24-word BIP39 phrase with a valid checksum.
///
/// `keetanetwork_crypto::utils::generate_random_passphrase` has no checksum,
/// so the web wallet shows a warning for its output on import.
pub fn generate_phrase() -> Result<Zeroizing<String>, WalletError> {
	let mut entropy = generate_random_bytes::<ENTROPY_BYTES>().map_err(|_| WalletError::Random)?;
	let phrase = phrase_from_entropy(&entropy);
	entropy.zeroize();
	phrase
}

/// Convert 32 bytes of entropy, such as a passkey PRF output, to a phrase.
pub fn phrase_from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, WalletError> {
	let entropy = Entropy::<ENTROPY_BYTES>::from_slice(entropy).ok_or(WalletError::InvalidEntropy)?;
	let mnemonics = entropy
		.to_mnemonics::<PHRASE_WORDS, CHECKSUM_BITS>()
		.map_err(|_| WalletError::InvalidEntropy)?;
	Ok(Zeroizing::new(mnemonics.to_string(&ENGLISH)))
}

/// Check that a phrase has 24 known words and a valid checksum.
pub fn validate_phrase(phrase: &str) -> Result<(), WalletError> {
	let normalized = Zeroizing::new(normalize_phrase(phrase));
	let mnemonics =
		Mnemonics::<PHRASE_WORDS>::from_string(&ENGLISH, &normalized).map_err(|_| WalletError::InvalidPhrase)?;
	Entropy::<ENTROPY_BYTES>::from_mnemonics::<PHRASE_WORDS, CHECKSUM_BITS>(&mnemonics)
		.map(|_| ())
		.map_err(|_| WalletError::InvalidPhrase)
}

#[derive(Debug, PartialEq, Eq, uniffi::Enum)]
pub enum PhraseStatus {
	Incomplete,
	Valid,
	InvalidWords { indices: Vec<u32> },
	BadChecksum,
}

/// Classify a phrase for the import screen, with the same states as the web wallet.
pub fn phrase_status(phrase: &str) -> PhraseStatus {
	let normalized = Zeroizing::new(normalize_phrase(phrase));
	let words = normalized.split(' ').filter(|word| !word.is_empty());
	let mut count: u32 = 0;
	let mut indices = Vec::new();
	for word in words {
		if ENGLISH.lookup_mnemonic(word).is_err() {
			indices.push(count);
		}
		count += 1;
	}
	if count as usize != PHRASE_WORDS {
		return PhraseStatus::Incomplete;
	}
	if !indices.is_empty() {
		return PhraseStatus::InvalidWords { indices };
	}
	match validate_phrase(&normalized) {
		Ok(()) => PhraseStatus::Valid,
		Err(_) => PhraseStatus::BadChecksum,
	}
}

fn normalize_phrase(phrase: &str) -> String {
	phrase
		.split_whitespace()
		.collect::<Vec<_>>()
		.join(" ")
		.to_lowercase()
}

/// Verify a signature with a `keeta_...` public key string.
pub fn verify(public_key: &str, message: &[u8], signature: &[u8]) -> Result<bool, WalletError> {
	let account = account_from_public_key_string(public_key).map_err(|_| WalletError::InvalidPublicKey)?;
	Ok(account_verify(&account, message, signature))
}

/// Encrypt to a `keeta_...` public key string.
pub fn encrypt(public_key: &str, plaintext: &[u8]) -> Result<Vec<u8>, WalletError> {
	let account = account_from_public_key_string(public_key).map_err(|_| WalletError::InvalidPublicKey)?;
	account_encrypt(&account, plaintext).map_err(|_| WalletError::Encrypt)
}

/// Holds the wallet seed. The seed has no accessor.
pub struct Wallet {
	seed: Zeroizing<[u8; ENTROPY_BYTES]>,
}

impl Wallet {
	pub fn from_phrase(phrase: &str) -> Result<Self, WalletError> {
		validate_phrase(phrase)?;
		Self::from_unverified_phrase(phrase)
	}

	/// Open a 24-word phrase without the BIP39 word and checksum checks.
	///
	/// The web wallet lets a user import such a phrase after a warning, so the same phrase must open here.
	pub fn from_unverified_phrase(phrase: &str) -> Result<Self, WalletError> {
		let normalized = Zeroizing::new(normalize_phrase(phrase));
		if normalized.split(' ').count() != PHRASE_WORDS {
			return Err(WalletError::InvalidPhrase);
		}
		let seed = seed_from_passphrase(normalized.as_str()).map_err(|_| WalletError::InvalidPhrase)?;
		Ok(Self { seed: Zeroizing::new(*seed.expose_secret()) })
	}

	pub fn public_key(&self, index: u32) -> Result<String, WalletError> {
		Ok(account_public_key_string(&self.account(index)?))
	}

	pub fn sign(&self, index: u32, message: &[u8]) -> Result<Vec<u8>, WalletError> {
		account_sign(&self.account(index)?, message).map_err(|_| WalletError::Sign)
	}

	/// Sign a 32-byte digest without hashing it, as `ExternalKeyPair` requires.
	pub fn sign_digest(&self, index: u32, digest: &[u8]) -> Result<Vec<u8>, WalletError> {
		AccountSigner::sign(self.account(index)?.as_ref(), digest, Some(SigningOptions::raw()))
			.map_err(|_| WalletError::Sign)
	}

	pub fn decrypt(&self, index: u32, ciphertext: &[u8]) -> Result<Vec<u8>, WalletError> {
		account_decrypt(&self.account(index)?, ciphertext).map_err(|_| WalletError::Decrypt)
	}

	fn account(&self, index: u32) -> Result<AccountRef, WalletError> {
		let keyable = Keyable::Seed(((*self.seed).into_secret(), index));
		let account =
			Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256K1))
				.map_err(|_| WalletError::Derivation)?;
		Ok(Arc::new(GenericAccount::EcdsaSecp256k1(account)))
	}
}
