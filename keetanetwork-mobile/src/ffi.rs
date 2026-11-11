//! UniFFI surface for the Swift and Kotlin layer.
//!
//! Phrases cross as bytes, because a host can overwrite a byte buffer but
//! cannot overwrite a Swift or Kotlin string.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use crate::{
	generate_phrase, phrase_from_entropy, verify, NormalizedPhrase, PhraseStatus, Wallet, WalletError, PHRASE_WORDS,
};

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

fn normalized_word(word: Vec<u8>) -> Result<Zeroizing<String>, WalletError> {
	let word = Zeroizing::new(word);
	let normalized = NormalizedPhrase::new(phrase_text(&word)?);
	if normalized.words().count() > 1 {
		return Err(WalletError::InvalidPhrase);
	}
	Ok(normalized.0)
}

struct DraftState {
	words: Vec<Zeroizing<String>>,
	warning_accepted: bool,
}

impl DraftState {
	fn phrase(&self) -> NormalizedPhrase {
		let words: Vec<&str> = self.words.iter().map(|word| word.as_str()).collect();
		NormalizedPhrase::new(&Zeroizing::new(words.join(" ")))
	}

	fn accepted_phrase(&self) -> Result<NormalizedPhrase, WalletError> {
		let phrase = self.phrase();
		match phrase.status() {
			PhraseStatus::Valid => Ok(phrase),
			PhraseStatus::Incomplete => Err(WalletError::InvalidPhrase),
			PhraseStatus::InvalidWords { .. } | PhraseStatus::BadChecksum if self.warning_accepted => Ok(phrase),
			PhraseStatus::InvalidWords { .. } | PhraseStatus::BadChecksum => Err(WalletError::WarningNotAccepted),
		}
	}
}

/// Holds the phrase during onboarding, so the host keeps only this handle.
#[derive(uniffi::Object)]
pub struct PhraseDraft {
	state: Mutex<DraftState>,
}

impl PhraseDraft {
	fn state(&self) -> MutexGuard<'_, DraftState> {
		self.state.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

#[uniffi::export]
impl PhraseDraft {
	#[uniffi::constructor]
	pub fn new() -> Arc<Self> {
		let words = (0..PHRASE_WORDS)
			.map(|_| Zeroizing::new(String::new()))
			.collect();
		Arc::new(Self { state: Mutex::new(DraftState { words, warning_accepted: false }) })
	}

	pub fn generate(&self) -> Result<(), WalletError> {
		let phrase = generate_phrase()?;
		let mut state = self.state();
		state.words = phrase
			.split(' ')
			.map(|word| Zeroizing::new(word.to_owned()))
			.collect();
		state.warning_accepted = false;
		Ok(())
	}

	/// Takes one word. An edit that changes the word also withdraws an accepted warning.
	pub fn set_word(&self, index: u32, word: Vec<u8>) -> Result<(), WalletError> {
		let word = normalized_word(word)?;
		let mut state = self.state();
		let slot = state
			.words
			.get_mut(index as usize)
			.ok_or(WalletError::InvalidPhrase)?;
		if *slot != word {
			*slot = word;
			state.warning_accepted = false;
		}
		Ok(())
	}

	/// Returns one word for display on a protected screen.
	pub fn word(&self, index: u32) -> Result<Vec<u8>, WalletError> {
		let state = self.state();
		let word = state
			.words
			.get(index as usize)
			.ok_or(WalletError::InvalidPhrase)?;
		Ok(word.as_bytes().to_vec())
	}

	pub fn word_matches(&self, index: u32, word: Vec<u8>) -> bool {
		let Ok(word) = normalized_word(word) else {
			return false;
		};
		self.state().words.get(index as usize) == Some(&word)
	}

	pub fn status(&self) -> PhraseStatus {
		self.state().phrase().status()
	}

	/// Has no effect if the current phrase has no warning.
	pub fn accept_warning(&self) {
		let mut state = self.state();
		state.warning_accepted =
			matches!(state.phrase().status(), PhraseStatus::InvalidWords { .. } | PhraseStatus::BadChecksum);
	}

	pub fn is_warning_accepted(&self) -> bool {
		self.state().warning_accepted
	}

	/// Opens a valid phrase, or a phrase with a warning that the user accepted.
	pub fn open_wallet(&self) -> Result<Arc<MobileWallet>, WalletError> {
		let phrase = self.state().accepted_phrase()?;
		let wallet = Wallet::from_normalized_phrase(&phrase)?;
		Ok(Arc::new(MobileWallet { wallet }))
	}

	/// Returns the phrase that `open_wallet` opens, for the vault to encrypt. The caller must overwrite these bytes.
	pub fn phrase_bytes(&self) -> Result<Vec<u8>, WalletError> {
		Ok(self.state().accepted_phrase()?.0.as_bytes().to_vec())
	}

	pub fn clear(&self) {
		let mut state = self.state();
		state.words = (0..PHRASE_WORDS)
			.map(|_| Zeroizing::new(String::new()))
			.collect();
		state.warning_accepted = false;
	}
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
