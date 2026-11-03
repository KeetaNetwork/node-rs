use keetanetwork_mobile::{encrypt, generate_phrase, Wallet};
use serde_json::json;

fn main() {
	let output_path = std::env::args()
		.nth(1)
		.expect("usage: emit_rust_vectors <output path>");
	let message = b"keeta mobile rust vector";
	let mut vectors = Vec::new();
	for _ in 0..5 {
		let phrase = generate_phrase().expect("generation must succeed");
		let wallet = Wallet::from_phrase(&phrase).expect("generated phrase must be valid");
		let mut accounts = Vec::new();
		for index in [0u32, 1, 7] {
			let public_key = wallet.public_key(index).expect("derivation must succeed");
			accounts.push(json!({
				"index": index,
				"publicKey": public_key,
				"signature": hex::encode(wallet.sign(index, message).expect("signing must succeed")),
				"ciphertext": hex::encode(encrypt(&public_key, message).expect("encryption must succeed")),
			}));
		}
		vectors.push(json!({ "phrase": phrase.as_str(), "accounts": accounts }));
	}
	let document = json!({ "message": hex::encode(message), "vectors": vectors });
	std::fs::write(output_path, document.to_string()).expect("output must be writable");
}
