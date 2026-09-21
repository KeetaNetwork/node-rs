//! docs.rs sets `DOCS_RS=1` and mounts crate source read-only.
//!
//! `generate_schema()` still writes `asn1/iso20022.asn` under the crate root, so
//! rustdoc fails before any crate docs are emitted. This test drives that path.

#![cfg(all(feature = "std", feature = "rasn", feature = "serde"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const WORKSPACE_ROOT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml"];

#[test]
fn docsrs_readonly_source_allows_asn1_build() {
	let Ok(crate_root) = PathBuf::from(env!("CARGO_MANIFEST_DIR")).canonicalize() else {
		panic!("CARGO_MANIFEST_DIR must canonicalize");
	};
	let Some(workspace) = crate_root.parent() else {
		panic!("keetanetwork-asn1 must live in the workspace");
	};

	let scratch = Scratch::create();
	stage_workspace(workspace, &crate_root, &scratch.path);

	// Force the `fs::write` branch: unchanged content would skip the source write.
	let schema = scratch.path.join("keetanetwork-asn1/asn1/iso20022.asn");
	fs::write(&schema, "stale schema to force generate_schema write\n")
		.expect("scratch schema must be writable before chmod");

	chmod_a_minus_w(scratch.path.join("keetanetwork-asn1"));

	let output = cargo_docsrs_build(&scratch.path);
	let log = command_log(&output);
	assert!(output.status.success(), "DOCS_RS=1 + read-only crate source must not panic in build.rs; got:\n{log}");
}

fn stage_workspace(workspace: &Path, crate_root: &Path, scratch: &Path) {
	for name in WORKSPACE_ROOT_FILES {
		fs::copy(workspace.join(name), scratch.join(name)).expect("workspace root file must copy");
	}

	let cargo_dir = scratch.join(".cargo");
	fs::create_dir_all(&cargo_dir).expect("scratch .cargo must exist");
	fs::copy(workspace.join(".cargo/config.toml"), cargo_dir.join("config.toml"))
		.expect(".cargo/config.toml must copy");

	copy_tree(crate_root, &scratch.join("keetanetwork-asn1"));
	link_sibling_members(workspace, scratch);
}

fn link_sibling_members(workspace: &Path, scratch: &Path) {
	let entries = fs::read_dir(workspace).expect("workspace must be readable");
	for entry in entries {
		let entry = entry.expect("workspace entry must be readable");
		let name = entry.file_name();
		let Some(name) = name.to_str() else {
			continue;
		};
		if !name.starts_with("keetanetwork-") || name == "keetanetwork-asn1" {
			continue;
		}
		let src = entry.path();
		if !src.is_dir() {
			continue;
		}
		std::os::unix::fs::symlink(src, scratch.join(name)).expect("sibling member must symlink");
	}
}

fn copy_tree(from: &Path, to: &Path) {
	fs::create_dir_all(to).expect("destination directory must exist");
	let entries = fs::read_dir(from).expect("source tree must be readable");
	for entry in entries {
		let entry = entry.expect("source entry must be readable");
		let src = entry.path();
		let dest = to.join(entry.file_name());
		if src.is_dir() {
			copy_tree(&src, &dest);
			continue;
		}
		fs::copy(&src, &dest).expect("source file must copy");
	}
}

fn cargo_docsrs_build(scratch: &Path) -> Output {
	let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
	Command::new(cargo)
		.args(["build", "-p", "keetanetwork-asn1", "--manifest-path"])
		.arg(scratch.join("Cargo.toml"))
		.env("DOCS_RS", "1")
		.env("CARGO_TARGET_DIR", scratch.join("target"))
		.env_remove("CARGO_BUILD_TARGET")
		.output()
		.expect("cargo build must spawn")
}

fn chmod_a_minus_w(path: PathBuf) {
	let status = Command::new("chmod")
		.args(["-R", "a-w"])
		.arg(&path)
		.status()
		.expect("chmod must spawn");
	assert!(status.success(), "chmod a-w must succeed on {}", path.display());
}

fn command_log(output: &Output) -> String {
	let stdout = String::from_utf8_lossy(&output.stdout);
	let stderr = String::from_utf8_lossy(&output.stderr);
	format!("status={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}", output.status.code())
}

struct Scratch {
	path: PathBuf,
}

impl Scratch {
	fn create() -> Self {
		let nanos = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_nanos())
			.unwrap_or(0);
		let path = std::env::temp_dir().join(format!("keetanetwork-asn1-docsrs-ro-{}-{nanos}", std::process::id()));
		fs::create_dir_all(&path).expect("scratch directory must exist");
		Self { path }
	}
}

impl Drop for Scratch {
	fn drop(&mut self) {
		let _ = Command::new("chmod")
			.args(["-R", "u+w"])
			.arg(&self.path)
			.status();
		let _ = fs::remove_dir_all(&self.path);
	}
}
