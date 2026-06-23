//! Bound Java SDK networked multisig example.
//!
//! Boots a reference node via [`E2eNode`], then runs the idiomatic Java
//! SDK (`bindings/java`) against it through Maven. The SDK loads the
//! `wasm32-wasip1` core module on the pure-JVM Chicory runtime
//! and performs node I/O over `java.net.http`.

use std::path::PathBuf;
use std::process::Command;

use keetanetwork_utils::node_harness::E2eNode;

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

/// A readiness field reported by the harness on startup.
fn ready_field(node: &E2eNode, field: &str) -> String {
	node.info()
		.get(field)
		.and_then(|value| value.as_str())
		.unwrap_or_default()
		.to_string()
}

/// The harness's trusted (genesis) signer seed: 32 bytes of `0x77` as hex.
fn trusted_seed() -> String {
	"77".repeat(32)
}

#[test]
#[ignore = "requires `make node-harness`, the wasm32-wasip1 module, and a Maven/JDK toolchain"]
fn java_sdk_transmits_against_e2e_node() -> Result<(), Box<dyn std::error::Error>> {
	let module = module_path();
	assert!(module.exists(), "build the core module first (missing {})", module.display());

	let mut harness = E2eNode::start()?;
	let api = ready_field(&harness, "api");
	let network = ready_field(&harness, "network");
	let base_token = ready_field(&harness, "baseToken");
	assert!(!api.is_empty(), "the harness must advertise an api URL");
	assert!(!network.is_empty(), "the harness must advertise a network id");
	assert!(!base_token.is_empty(), "the harness must advertise a base token");

	// Mint a supply to the trusted account so it has a chain head to build on.
	harness.request("init_supply", serde_json::json!({ "amount": "1000000" }))?;

	let output = Command::new(maven())
		.current_dir(sdk_dir())
		.args(["-q", "-B", "compile", "exec:java"])
		.env("WASI_P1_MODULE", &module)
		.env("KEETA_API", &api)
		.env("KEETA_NETWORK", &network)
		.env("KEETA_BASE_TOKEN", &base_token)
		.env("KEETA_TRUSTED_SEED", trusted_seed())
		.output()?;

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(output.status.success(), "the Java example must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
	assert!(stdout.contains("MULTISIG_OK"), "the Java must confirm a multisig transmit\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");

	Ok(())
}
