use keetanetwork_bindings::account::{account_encrypt, account_from_public_key_string};
use keetanetwork_crypto::prelude::{ExposeSecret, SigningOptions};
use keetanetwork_crypto::utils::seed_from_passphrase;
use keetanetwork_mobile::ffi::{
	generate_phrase_bytes, phrase_bytes_from_entropy, verify_signature, MobileWallet, PhraseDraft,
};
use keetanetwork_mobile::{PhraseStatus, WalletError};
use serde::Deserialize;
use std::error::Error;
use std::sync::Arc;

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Deserialize)]
struct Fixture {
	message: String,
	vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
	entropy: String,
	seed: String,
	phrase: String,
	accounts: Vec<AccountVector>,
}

#[derive(Deserialize)]
struct AccountVector {
	index: u32,
	#[serde(rename = "publicKey")]
	public_key: String,
	signature: String,
	ciphertext: String,
}

#[derive(Deserialize)]
struct UnverifiedFixture {
	message: String,
	vectors: Vec<UnverifiedVector>,
}

#[derive(Deserialize)]
struct UnverifiedVector {
	phrase: String,
	#[serde(rename = "publicKey")]
	public_key: String,
	signature: String,
}

fn debug_text(error: impl std::fmt::Debug) -> String {
	format!("{error:?}")
}

fn fixture() -> Result<Fixture, serde_json::Error> {
	serde_json::from_str(include_str!("fixtures/web-vectors.json"))
}

fn draft_with_words<Word: AsRef<str>>(words: &[Word]) -> Result<Arc<PhraseDraft>, WalletError> {
	let draft = PhraseDraft::new();
	for (index, word) in (0u32..).zip(words) {
		draft.set_word(index, word.as_ref().as_bytes().to_vec())?;
	}
	Ok(draft)
}

#[test]
fn phrase_from_entropy_matches_the_web_wallet() -> TestResult {
	for vector in fixture()?.vectors {
		let entropy = hex::decode(&vector.entropy)?;
		assert_eq!(phrase_bytes_from_entropy(entropy), Ok(vector.phrase.into_bytes()));
	}
	assert_eq!(phrase_bytes_from_entropy(vec![0; 31]), Err(WalletError::InvalidEntropy));
	Ok(())
}

#[test]
fn seeds_and_public_keys_match_the_web_wallet() -> TestResult {
	for vector in fixture()?.vectors {
		let seed = seed_from_passphrase(&vector.phrase)?;
		assert_eq!(hex::encode(seed.expose_secret()), vector.seed);
		let wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes())?;
		for account in vector.accounts {
			assert_eq!(wallet.public_key(account.index), Ok(account.public_key));
		}
	}
	Ok(())
}

#[test]
fn web_signatures_verify_and_rust_signatures_match() -> TestResult {
	let fixture = fixture()?;
	let message = hex::decode(&fixture.message)?;
	let digest = SigningOptions::default()
		.digest(&message)
		.map_err(debug_text)?;
	for vector in fixture.vectors {
		let wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes())?;
		for account in vector.accounts {
			let web_signature = hex::decode(&account.signature)?;
			assert_eq!(verify_signature(account.public_key.clone(), message.clone(), web_signature.clone()), Ok(true));
			assert_eq!(wallet.sign(account.index, message.clone()), Ok(web_signature.clone()));
			assert_eq!(wallet.sign_digest(account.index, digest.to_vec()), Ok(web_signature));
			assert_eq!(wallet.sign_digest(account.index, message.clone()), Err(WalletError::InvalidDigest));
		}
	}
	assert_eq!(verify_signature("not a key".to_owned(), message, Vec::new()), Err(WalletError::InvalidPublicKey));
	Ok(())
}

#[test]
fn web_ciphertext_decrypts_in_rust() -> TestResult {
	let fixture = fixture()?;
	let message = hex::decode(&fixture.message)?;
	for vector in fixture.vectors {
		let wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes())?;
		for account in vector.accounts {
			let web_ciphertext = hex::decode(&account.ciphertext)?;
			assert_eq!(wallet.decrypt(account.index, web_ciphertext), Ok(message.clone()));

			let public_account = account_from_public_key_string(&account.public_key).map_err(debug_text)?;
			let rust_ciphertext = account_encrypt(&public_account, &message).map_err(debug_text)?;
			assert_eq!(wallet.decrypt(account.index, rust_ciphertext), Ok(message.clone()));
		}
	}
	Ok(())
}

#[test]
fn generated_phrase_has_24_words_and_a_valid_checksum() -> TestResult {
	let phrase = generate_phrase_bytes()?;
	assert_eq!(std::str::from_utf8(&phrase)?.split(' ').count(), 24);
	assert!(MobileWallet::from_phrase_bytes(phrase).is_ok());
	Ok(())
}

#[test]
fn phrase_with_a_wrong_checksum_is_rejected() {
	let phrase = vec!["abandon"; 24].join(" ");
	assert_eq!(MobileWallet::from_phrase_bytes(phrase.into_bytes()).err(), Some(WalletError::InvalidPhrase));
	assert_eq!(WalletError::InvalidPhrase.to_string(), "InvalidPhrase");

	/* A host can pass any bytes, so the phrase text may not be UTF-8 */
	assert_eq!(MobileWallet::from_phrase_bytes(vec![0xff]).err(), Some(WalletError::InvalidPhrase));
	assert!(!PhraseDraft::new().word_matches(0, vec![0xff]));
}

#[test]
fn phrase_status_matches_the_web_import_states() -> TestResult {
	let valid = fixture()?.vectors.remove(0).phrase;
	let valid_words: Vec<String> = valid.split(' ').map(str::to_owned).collect();
	let padded_words: Vec<String> = valid_words
		.iter()
		.map(|word| format!("  {}\t", word.to_uppercase()))
		.collect();
	let mut invalid_edges = vec!["abandon".to_owned(); 24];
	invalid_edges[0] = "keetaword".to_owned();
	invalid_edges[23] = "keetaword".to_owned();
	let mut non_ascii_word = vec!["abandon".to_owned(); 24];
	non_ascii_word[5] = "\u{c1}BACO".to_owned();

	let cases = [
		(Vec::new(), PhraseStatus::Incomplete),
		(valid_words[..2].to_vec(), PhraseStatus::Incomplete),
		(valid_words.clone(), PhraseStatus::Valid),
		(padded_words, PhraseStatus::Valid),
		(vec!["abandon".to_owned(); 24], PhraseStatus::BadChecksum),
		(invalid_edges, PhraseStatus::InvalidWords { indices: vec![0, 23] }),
		(non_ascii_word, PhraseStatus::InvalidWords { indices: vec![5] }),
	];
	for (words, expected) in cases {
		assert_eq!(draft_with_words(&words)?.status(), expected);
	}
	Ok(())
}

#[test]
fn phrase_draft_follows_the_web_import_flow() -> TestResult {
	let valid = fixture()?.vectors.remove(0).phrase;
	let words: Vec<&str> = valid.split(' ').collect();
	let expected_public_key = MobileWallet::from_phrase_bytes(valid.clone().into_bytes())?.public_key(0)?;

	let draft = PhraseDraft::new();
	assert_eq!(draft.open_wallet().err(), Some(WalletError::InvalidPhrase));
	assert_eq!(draft.phrase_bytes(), Err(WalletError::InvalidPhrase));
	draft.accept_warning();
	assert!(!draft.is_warning_accepted());

	/* A slot holds one word, so a whole phrase leaves the slot unchanged */
	assert_eq!(draft.set_word(0, valid.clone().into_bytes()), Err(WalletError::InvalidPhrase));
	assert_eq!(draft.word(0), Ok(Vec::new()));

	for (index, word) in (0u32..).zip(&words) {
		draft.set_word(index, format!(" {} ", word.to_uppercase()).into_bytes())?;
	}
	assert_eq!(draft.phrase_bytes(), Ok(valid.clone().into_bytes()));
	assert_eq!(draft.open_wallet()?.public_key(0), Ok(expected_public_key.clone()));
	assert_eq!(draft.word(23), Ok(words[23].as_bytes().to_vec()));
	assert!(draft.word_matches(0, words[0].to_uppercase().into_bytes()));
	assert!(!draft.word_matches(0, b"keetaword".to_vec()));
	assert!(!draft.word_matches(0, valid.clone().into_bytes()));
	assert!(!draft.word_matches(24, words[0].as_bytes().to_vec()));
	assert_eq!(draft.set_word(24, b"abandon".to_vec()), Err(WalletError::InvalidPhrase));
	assert_eq!(draft.set_word(u32::MAX, b"abandon".to_vec()), Err(WalletError::InvalidPhrase));
	assert_eq!(draft.word(u32::MAX), Err(WalletError::InvalidPhrase));

	draft.accept_warning();
	assert!(!draft.is_warning_accepted());

	/* An invalid word needs the warning before the phrase can open or go to the vault */
	draft.set_word(1, b"keetaword".to_vec())?;
	assert_eq!(draft.status(), PhraseStatus::InvalidWords { indices: vec![1] });
	assert_eq!(draft.open_wallet().err(), Some(WalletError::WarningNotAccepted));
	assert_eq!(draft.phrase_bytes(), Err(WalletError::WarningNotAccepted));
	draft.accept_warning();
	assert!(draft.is_warning_accepted());
	assert!(draft.open_wallet().is_ok());
	assert!(draft.phrase_bytes().is_ok());

	draft.set_word(1, b"keetaword".to_vec())?;
	assert!(draft.is_warning_accepted());
	draft.set_word(1, b"otherword".to_vec())?;
	assert!(!draft.is_warning_accepted());
	assert_eq!(draft.open_wallet().err(), Some(WalletError::WarningNotAccepted));

	draft.generate()?;
	assert_eq!(draft.status(), PhraseStatus::Valid);
	draft.clear();
	assert_eq!(draft.status(), PhraseStatus::Incomplete);
	assert_eq!(draft.phrase_bytes(), Err(WalletError::InvalidPhrase));
	Ok(())
}

#[test]
fn unverified_phrases_open_the_same_account_as_the_web_wallet() -> TestResult {
	let fixture: UnverifiedFixture = serde_json::from_str(include_str!("fixtures/web-unverified-vectors.json"))?;
	let message = hex::decode(&fixture.message)?;
	for vector in fixture.vectors {
		let phrase = vector.phrase.into_bytes();
		assert_eq!(MobileWallet::from_phrase_bytes(phrase.clone()).err(), Some(WalletError::InvalidPhrase));

		let wallet = MobileWallet::from_unverified_phrase_bytes(phrase.clone())?;
		assert_eq!(wallet.public_key(0), Ok(vector.public_key.clone()));
		assert_eq!(wallet.sign(0, message.clone()), Ok(hex::decode(&vector.signature)?));

		let words: Vec<&str> = std::str::from_utf8(&phrase)?.split(' ').collect();
		let draft = draft_with_words(&words)?;
		assert_eq!(draft.open_wallet().err(), Some(WalletError::WarningNotAccepted));
		draft.accept_warning();
		assert_eq!(draft.open_wallet()?.public_key(0), Ok(vector.public_key));
	}
	assert_eq!(
		MobileWallet::from_unverified_phrase_bytes(b"abandon abandon".to_vec()).err(),
		Some(WalletError::InvalidPhrase)
	);
	Ok(())
}
