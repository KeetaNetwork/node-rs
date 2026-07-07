//! Cross-implementation account parity for the bound Java SDK.

use std::path::PathBuf;
use std::process::Command;

use keetanetwork_utils::node_harness::RefHarness;
use serde_json::{json, Value};

/// The algorithms exercised across every constructor and direction.
const ALGORITHMS: [&str; 3] = ["ed25519", "ecdsa_secp256k1", "ecdsa_secp256r1"];

/// A fixed 32-byte seed (hex) shared by both implementations.
const SEED_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// The derivation index applied to the seed and passphrase.
const INDEX: u32 = 0;

/// A passphrase long enough to satisfy the reference derivation strength check.
const PASSPHRASE: &str = "this is the example length for a sufficient passphrase to be set secured";

/// The message signed in one implementation and verified in the other.
const MESSAGE: &[u8] = b"keeta cross-impl account parity";

/// The plaintext encrypted in one implementation and decrypted in the other.
const PLAINTEXT: &[u8] = b"round-trip ciphertext payload";

/// Locate the prebuilt P1 core module.
fn module_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P1_MODULE") {
		return PathBuf::from(path);
	}

	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/wasm32-wasip1/debug/keetanetwork_client_wasi.wasm")
}

/// The Java SDK project directory.
fn sdk_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../bindings/java")
}

/// The Maven launcher, overridable for non-standard toolchains.
fn maven() -> String {
	std::env::var("MAVEN_BIN").unwrap_or_else(|_| String::from("mvn"))
}

/// Reconstruct accounts in Java and return its emitted signatures/ciphertexts.
fn java_parity(module: &PathBuf, reference: &Value) -> Result<Value, Box<dyn std::error::Error>> {
	let output = Command::new(maven())
		.current_dir(sdk_dir())
		.args(["-q", "-B", "compile", "exec:java", "-Dexec.mainClass=network.keeta.wasi.harness.AccountParity"])
		.env("WASI_P1_MODULE", module)
		.env("KEETA_PARITY_INPUT", reference.to_string())
		.env("KEETA_MESSAGE_HEX", hex::encode(MESSAGE))
		.env("KEETA_PLAINTEXT_HEX", hex::encode(PLAINTEXT))
		.env("KEETA_PASSPHRASE", PASSPHRASE)
		.env("KEETA_INDEX", INDEX.to_string())
		.env("KEETA_ALGORITHMS", ALGORITHMS.join(","))
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the Java parity run must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(
		stdout.contains("ACCOUNT_PARITY_OK"),
		"the Java SDK must confirm parity\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);

	let line = stdout
		.lines()
		.find_map(|line| line.strip_prefix("PARITY_RESULT:"))
		.ok_or("the Java SDK must emit a PARITY_RESULT line")?;
	Ok(serde_json::from_str(line)?)
}

#[test]
fn java_sdk_accounts_round_trip_against_reference() -> Result<(), Box<dyn std::error::Error>> {
	let module = module_path();
	assert!(module.exists(), "build the core module first (missing {})", module.display());

	let mut reference_sdk = RefHarness::start()?;
	let reference = reference_sdk.request(
		"account_generate",
		json!({
			"seedHex": SEED_HEX,
			"index": INDEX,
			"passphrase": PASSPHRASE,
			"messageHex": hex::encode(MESSAGE),
			"plaintextHex": hex::encode(PLAINTEXT),
			"algorithms": ALGORITHMS,
		}),
	)?;

	let java_results = java_parity(&module, &reference)?;
	let verdict = reference_sdk.request(
		"account_verify",
		json!({
			"seedHex": SEED_HEX,
			"index": INDEX,
			"messageHex": hex::encode(MESSAGE),
			"plaintextHex": hex::encode(PLAINTEXT),
			"results": java_results,
		}),
	)?;

	assert_eq!(verdict["ok"], Value::Bool(true), "the reference SDK must accept every Java artifact");

	Ok(())
}
