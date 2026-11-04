use keetanetwork_crypto::prelude::SigningOptions;
use keetanetwork_mobile::ffi::{
	generate_phrase_bytes, phrase_bytes_from_entropy, verify_signature, MobileWallet, PhraseDraft,
};
use keetanetwork_mobile::{
	encrypt, generate_phrase, phrase_from_entropy, phrase_status, validate_phrase, verify, PhraseStatus, Wallet,
	WalletError,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
	message: String,
	vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
	entropy: String,
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

fn fixture() -> Fixture {
	serde_json::from_str(include_str!("fixtures/web-vectors.json")).expect("fixture must parse")
}

#[test]
fn phrase_from_entropy_matches_the_web_wallet() {
	for vector in fixture().vectors {
		let entropy = hex::decode(&vector.entropy).expect("entropy must be hex");
		let phrase = phrase_from_entropy(&entropy).expect("entropy must convert");
		assert_eq!(phrase.as_str(), vector.phrase);
		assert_eq!(phrase_bytes_from_entropy(entropy), Ok(vector.phrase.into_bytes()));
	}
	assert_eq!(phrase_bytes_from_entropy(vec![0; 31]), Err(WalletError::InvalidEntropy));
}

#[test]
fn public_keys_match_the_web_wallet() {
	for vector in fixture().vectors {
		let wallet = Wallet::from_phrase(&vector.phrase).expect("phrase must be valid");
		let mobile_wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes()).expect("phrase must be valid");
		for account in vector.accounts {
			assert_eq!(
				wallet
					.public_key(account.index)
					.expect("derivation must succeed"),
				account.public_key
			);
			assert_eq!(mobile_wallet.public_key(account.index), Ok(account.public_key));
		}
	}
}

#[test]
fn web_signatures_verify_and_rust_signatures_match() {
	let fixture = fixture();
	let message = hex::decode(&fixture.message).expect("message must be hex");
	for vector in fixture.vectors {
		let wallet = Wallet::from_phrase(&vector.phrase).expect("phrase must be valid");
		let mobile_wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes()).expect("phrase must be valid");
		for account in vector.accounts {
			let web_signature = hex::decode(&account.signature).expect("signature must be hex");
			assert!(verify(&account.public_key, &message, &web_signature).expect("public key must parse"));
			assert_eq!(verify_signature(account.public_key.clone(), message.clone(), web_signature.clone()), Ok(true));
			assert_eq!(mobile_wallet.sign(account.index, message.clone()), Ok(web_signature.clone()));
			let rust_signature = wallet
				.sign(account.index, &message)
				.expect("signing must succeed");
			assert!(verify(&account.public_key, &message, &rust_signature).expect("public key must parse"));
			assert_eq!(hex::encode(rust_signature), account.signature);
			let digest = SigningOptions::default()
				.digest(&message)
				.expect("digest must succeed");
			let digest_signature = wallet
				.sign_digest(account.index, &digest)
				.expect("digest signing must succeed");
			assert_eq!(hex::encode(digest_signature), account.signature);
			assert_eq!(mobile_wallet.sign_digest(account.index, digest.to_vec()), Ok(web_signature));
			assert_eq!(wallet.sign_digest(account.index, &message), Err(WalletError::Sign));
		}
	}
	assert_eq!(verify("not a key", &message, &[]), Err(WalletError::InvalidPublicKey));
}

#[test]
fn web_ciphertext_decrypts_in_rust() {
	let fixture = fixture();
	let message = hex::decode(&fixture.message).expect("message must be hex");
	for vector in fixture.vectors {
		let wallet = Wallet::from_phrase(&vector.phrase).expect("phrase must be valid");
		let mobile_wallet = MobileWallet::from_phrase_bytes(vector.phrase.into_bytes()).expect("phrase must be valid");
		for account in vector.accounts {
			let ciphertext = hex::decode(&account.ciphertext).expect("ciphertext must be hex");
			assert_eq!(
				wallet
					.decrypt(account.index, &ciphertext)
					.expect("decryption must succeed"),
				message
			);
			assert_eq!(mobile_wallet.decrypt(account.index, ciphertext), Ok(message.clone()));

			let rust_ciphertext = encrypt(&account.public_key, &message).expect("encryption must succeed");
			assert_eq!(wallet.decrypt(account.index, &rust_ciphertext), Ok(message.clone()));
		}
	}
	assert_eq!(encrypt("not a key", &message), Err(WalletError::InvalidPublicKey));
}

#[test]
fn generated_phrase_has_24_words_and_a_valid_checksum() {
	let phrase = generate_phrase().expect("generation must succeed");
	assert_eq!(phrase.split(' ').count(), 24);
	assert_eq!(validate_phrase(&phrase), Ok(()));

	let phrase_bytes = generate_phrase_bytes().expect("generation must succeed");
	assert!(MobileWallet::from_phrase_bytes(phrase_bytes).is_ok());
}

#[test]
fn phrase_with_a_wrong_checksum_is_rejected() {
	let phrase = "abandon ".repeat(23) + "abandon";
	assert_eq!(validate_phrase(&phrase), Err(WalletError::InvalidPhrase));
	assert!(matches!(Wallet::from_phrase(&phrase), Err(WalletError::InvalidPhrase)));
	assert!(matches!(MobileWallet::from_phrase_bytes(phrase.into_bytes()), Err(WalletError::InvalidPhrase)));
	assert_eq!(WalletError::InvalidPhrase.to_string(), "InvalidPhrase");

	/* A host can pass any bytes, so the phrase text may not be UTF-8 */
	assert!(matches!(MobileWallet::from_phrase_bytes(vec![0xff]), Err(WalletError::InvalidPhrase)));
	assert!(!PhraseDraft::new().word_matches(0, vec![0xff]));
}

#[test]
fn phrase_status_matches_the_web_import_states() {
	let valid = fixture().vectors.remove(0).phrase;
	assert_eq!(phrase_status(&valid), PhraseStatus::Valid);

	let draft = PhraseDraft::new();
	assert_eq!(draft.status(), PhraseStatus::Incomplete);
	let words: Vec<&str> = valid.split(' ').collect();
	for (index, word) in (0u32..).zip(&words) {
		draft
			.set_word(index, format!(" {} ", word.to_uppercase()).into_bytes())
			.expect("index must exist");
	}
	assert_eq!(draft.status(), PhraseStatus::Valid);
	assert_eq!(draft.phrase_bytes(), valid.as_bytes());
	assert_eq!(draft.word(23).expect("index must exist"), words[23].as_bytes());
	assert!(draft.word_matches(0, words[0].to_uppercase().into_bytes()));
	assert!(!draft.word_matches(0, b"keetaword".to_vec()));
	assert!(!draft.word_matches(24, words[0].as_bytes().to_vec()));
	assert_eq!(draft.set_word(24, b"abandon".to_vec()), Err(WalletError::InvalidPhrase));
	assert_eq!(
		draft
			.open_wallet()
			.expect("24 words must open")
			.public_key(0),
		Wallet::from_phrase(&valid)
			.expect("phrase must be valid")
			.public_key(0)
	);

	draft
		.set_word(1, b"keetaword".to_vec())
		.expect("index must exist");
	assert_eq!(draft.status(), PhraseStatus::InvalidWords { indices: vec![1] });
	draft.accept_warning();
	assert!(draft.is_warning_accepted());
	draft
		.set_word(1, b"keetaword".to_vec())
		.expect("index must exist");
	assert!(draft.is_warning_accepted());
	draft
		.set_word(1, b"abandon".to_vec())
		.expect("index must exist");
	assert!(!draft.is_warning_accepted());

	draft.generate().expect("generation must succeed");
	assert_eq!(draft.status(), PhraseStatus::Valid);
	draft.clear();
	assert_eq!(draft.status(), PhraseStatus::Incomplete);
	assert_eq!(draft.phrase_bytes(), " ".repeat(23).into_bytes());

	assert_eq!(phrase_status(&format!("  {}  ", valid.to_uppercase().replace(' ', "   "))), PhraseStatus::Valid);
	assert_eq!(phrase_status("abandon abandon"), PhraseStatus::Incomplete);
	assert_eq!(phrase_status(""), PhraseStatus::Incomplete);
	assert_eq!(phrase_status(&"abandon ".repeat(24)), PhraseStatus::BadChecksum);
	assert_eq!(
		phrase_status(&format!("keetaword {}keetaword", "abandon ".repeat(22))),
		PhraseStatus::InvalidWords { indices: vec![0, 23] }
	);
}

#[test]
fn unverified_phrases_open_the_same_account_as_the_web_wallet() {
	let fixture: serde_json::Value =
		serde_json::from_str(include_str!("fixtures/web-unverified-vectors.json")).expect("fixture must parse");
	let message = hex::decode(fixture["message"].as_str().expect("message must be text")).expect("message must be hex");
	for vector in fixture["vectors"]
		.as_array()
		.expect("vectors must be a list")
	{
		let phrase = vector["phrase"].as_str().expect("phrase must be text");
		assert_ne!(phrase_status(phrase), PhraseStatus::Valid);
		assert!(matches!(Wallet::from_phrase(phrase), Err(WalletError::InvalidPhrase)));

		let wallet = Wallet::from_unverified_phrase(phrase).expect("24 words must open");
		assert_eq!(
			wallet.public_key(0).expect("derivation must succeed"),
			vector["publicKey"].as_str().expect("key must be text")
		);
		let mobile_wallet =
			MobileWallet::from_unverified_phrase_bytes(phrase.as_bytes().to_vec()).expect("24 words must open");
		assert_eq!(mobile_wallet.public_key(0), wallet.public_key(0));
		let signature = wallet.sign(0, &message).expect("signing must succeed");
		assert_eq!(
			hex::encode(signature),
			vector["signature"]
				.as_str()
				.expect("signature must be text")
		);
	}
	assert!(matches!(Wallet::from_unverified_phrase("abandon abandon"), Err(WalletError::InvalidPhrase)));
}
