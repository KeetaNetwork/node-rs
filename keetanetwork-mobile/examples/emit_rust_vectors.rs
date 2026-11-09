use keetanetwork_bindings::account::{account_encrypt, account_from_public_key_string};
use keetanetwork_mobile::ffi::{generate_phrase_bytes, MobileWallet};
use serde_json::json;

fn main() {
	let output_path = std::env::args()
		.nth(1)
		.expect("usage: emit_rust_vectors <output path>");
	let message = b"keeta mobile rust vector".to_vec();
	let mut vectors = Vec::new();
	for _ in 0..5 {
		let phrase = generate_phrase_bytes().expect("generation must succeed");
		let wallet = MobileWallet::from_phrase_bytes(phrase.clone()).expect("generated phrase must be valid");
		let mut accounts = Vec::new();
		for index in [0u32, 1, 7] {
			let public_key = wallet.public_key(index).expect("derivation must succeed");
			let account = account_from_public_key_string(&public_key).expect("public key must parse");
			accounts.push(json!({
				"index": index,
				"publicKey": public_key,
				"signature": hex::encode(wallet.sign(index, message.clone()).expect("signing must succeed")),
				"ciphertext": hex::encode(account_encrypt(&account, &message).expect("encryption must succeed")),
			}));
		}
		let phrase = String::from_utf8(phrase).expect("phrase must be text");
		vectors.push(json!({ "phrase": phrase, "accounts": accounts }));
	}
	let document = json!({ "message": hex::encode(&message), "vectors": vectors });
	std::fs::write(output_path, document.to_string()).expect("output must be writable");
}
