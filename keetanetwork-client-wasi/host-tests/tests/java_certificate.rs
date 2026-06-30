//! Base-certificate metadata check for the bound Java SDK.
//!
//! Drives the Java `CertificateMetadata` harness against the P1 core module: no
//! node, no reference harness, no network.

use std::path::PathBuf;
use std::process::Command;

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

#[test]
fn java_sdk_reports_certificate_metadata() {
	let module = module_path();
	assert!(module.exists(), "build the core module first (missing {})", module.display());

	let output = Command::new(maven())
		.current_dir(sdk_dir())
		.args(["-q", "-B", "compile", "exec:java", "-Dexec.mainClass=network.keeta.wasi.harness.CertificateMetadata"])
		.env("WASI_P1_MODULE", &module)
		.output()
		.expect("the Java certificate-metadata run must launch");

	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		output.status.success(),
		"the Java certificate-metadata run must exit zero\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);
	assert!(
		stdout.contains("CERTIFICATE_METADATA_OK"),
		"the Java SDK must confirm the certificate metadata\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
	);
}
