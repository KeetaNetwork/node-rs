//! Test harness for the reference TypeScript implementation.
//!
//! Resolves the reference implementation distribution portably.

use core::fmt::Display;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Lines, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use serde_json::{Map, Value};
use snafu::Snafu;

/// Errors raised while resolving or driving the reference implementation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum HarnessError {
	/// The reference implementation distribution could not be located.
	#[snafu(display(
		"reference implementation not found at {} (run `make node-harness` or set KEETANET_NODE_DIST)",
		searched.display()
	))]
	DistNotFound {
		/// The path that was searched
		searched: PathBuf,
	},

	/// Spawning or talking to the `node` process failed.
	#[snafu(display("node process I/O failed: {source}"))]
	Io {
		/// The underlying I/O error
		source: std::io::Error,
	},

	/// A script exited unsuccessfully.
	#[snafu(display("node script failed (status {status:?}): {stderr}"))]
	ScriptFailed {
		/// The exit code, when one exists
		status: Option<i32>,
		/// Captured standard error output
		stderr: String,
	},

	/// The harness process closed its output stream unexpectedly.
	#[snafu(display("harness process ended unexpectedly"))]
	UnexpectedEof,

	/// A protocol line was not valid JSON.
	#[snafu(display("invalid harness protocol line: {source}"))]
	Protocol {
		/// The underlying JSON error
		source: serde_json::Error,
	},

	/// The harness reported a command failure.
	#[snafu(display("harness command {command} failed: {message}"))]
	CommandFailed {
		/// The command that failed
		command: String,
		/// The error message reported by the harness
		message: String,
	},

	/// Request parameters were neither a JSON object nor null.
	#[snafu(display("harness command {command} requires object params, got {params}"))]
	NonObjectParams {
		/// The command that was attempted
		command: String,
		/// The rejected parameters
		params: Value,
	},
}

impl From<std::io::Error> for HarnessError {
	fn from(source: std::io::Error) -> Self {
		Self::Io { source }
	}
}

impl From<serde_json::Error> for HarnessError {
	fn from(source: serde_json::Error) -> Self {
		Self::Protocol { source }
	}
}

/// The `node-harness` directory inside this crate.
pub fn harness_dir() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("node-harness")
}

/// Resolve a compiled harness script (`make node-harness` builds them).
pub fn script_path(name: impl AsRef<Path>) -> Result<PathBuf, HarnessError> {
	let script = harness_dir()
		.join("dist")
		.join(name.as_ref())
		.with_extension("js");

	if !script.exists() {
		return Err(HarnessError::DistNotFound { searched: script });
	}

	Ok(script)
}

/// Resolve the reference implementation `dist` directory.
pub fn dist_dir() -> Result<PathBuf, HarnessError> {
	let dist = match std::env::var_os("KEETANET_NODE_DIST") {
		Some(path) => PathBuf::from(path),
		None => harness_dir().join("node_modules/@keetanetwork/keetanet-node/dist"),
	};

	if !dist.join("lib/block/index.js").exists() {
		return Err(HarnessError::DistNotFound { searched: dist });
	}

	Ok(dist)
}

/// Run a one-shot `node` script to completion, returning its output.
///
/// The script receives the resolved dist directory as its first argument,
/// followed by `args`. When `stdin_data` is provided it is written to the
/// script's standard input.
pub fn run_node_script(
	script: impl AsRef<Path>,
	args: impl IntoIterator<Item = impl AsRef<OsStr>>,
	stdin_data: Option<&[u8]>,
) -> Result<Output, HarnessError> {
	let dist = dist_dir()?;

	let mut command = Command::new("node");
	command
		.arg(script.as_ref())
		.arg(&dist)
		.args(args)
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());

	if stdin_data.is_some() {
		command.stdin(Stdio::piped());
	} else {
		command.stdin(Stdio::null());
	}

	let mut child = command.spawn()?;

	if let (Some(data), Some(stdin)) = (stdin_data, child.stdin.as_mut()) {
		stdin.write_all(data)?;
	}

	drop(child.stdin.take());

	let output = child.wait_with_output()?;
	if !output.status.success() {
		return Err(HarnessError::ScriptFailed {
			status: output.status.code(),
			stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
		});
	}

	Ok(output)
}

/// A live local reference node driven over a JSON-lines protocol.
///
/// Each command written to the harness produces exactly one JSON response
/// line; harness diagnostics go to standard error.
pub struct E2eNode {
	child: Child,
	stdin: ChildStdin,
	lines: Lines<BufReader<ChildStdout>>,
	ready: Value,
}

impl E2eNode {
	/// Spawn the harness script and wait for it to report readiness.
	pub fn start() -> Result<Self, HarnessError> {
		Self::start_with_args(&[])
	}

	/// Spawn a fee-enforcing harness node that charges `amount` base tokens
	/// (paid to the representative) on every transaction, so the fee block
	/// origination path can be exercised end to end.
	pub fn start_with_fee(amount: u64) -> Result<Self, HarnessError> {
		Self::start_with_args(&[&format!("--fee={amount}")])
	}

	/// Spawn a peered cluster of `reps` representative nodes (P2P enabled)
	/// sharing one trusted/genesis account, so the multi-representative
	/// fan-out, quorum, and convergence paths can be exercised end to end.
	pub fn start_cluster(reps: usize) -> Result<Self, HarnessError> {
		let arg = format!("--reps={reps}");
		Self::start_with_args(&[arg.as_str()])
	}

	/// Spawn the harness script with extra argv, waiting for readiness.
	fn start_with_args(extra: &[&str]) -> Result<Self, HarnessError> {
		let dist = dist_dir()?;
		let script = script_path("e2e-node")?;

		let mut child = Command::new("node")
			.arg(&script)
			.arg(&dist)
			.args(extra)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child.stdin.take().ok_or(HarnessError::UnexpectedEof)?;
		let stdout = child.stdout.take().ok_or(HarnessError::UnexpectedEof)?;

		let mut node = Self { child, stdin, lines: BufReader::new(stdout).lines(), ready: Value::Null };

		// The harness emits a single ready line once the node is running.
		let ready = node.read_response("start")?;
		if ready.get("event").and_then(Value::as_str) != Some("ready") {
			return Err(HarnessError::CommandFailed { command: "start".to_string(), message: ready.to_string() });
		}

		node.ready = ready;

		Ok(node)
	}

	/// The readiness payload reported by the harness on startup (network
	/// id, base token, trusted and representative accounts).
	pub fn info(&self) -> &Value {
		&self.ready
	}

	/// Send a command and return its (successful) JSON response.
	///
	/// `params` must be a JSON object (or null for parameter-less commands)
	/// so the command name can always be attached to the payload.
	pub fn request(&mut self, command: &str, params: Value) -> Result<Value, HarnessError> {
		let mut object = match params {
			Value::Object(map) => map,
			Value::Null => Map::new(),
			other => {
				return Err(HarnessError::NonObjectParams { command: command.to_string(), params: other });
			}
		};

		object.insert("cmd".to_string(), Value::String(command.to_string()));

		let message = Value::Object(object);
		writeln!(self.stdin, "{message}")?;

		self.stdin.flush()?;
		self.read_response(command)
	}

	/// Read one protocol line, surfacing harness-reported errors.
	fn read_response(&mut self, command: impl Display) -> Result<Value, HarnessError> {
		let line = self.lines.next().ok_or(HarnessError::UnexpectedEof)??;
		let value: Value = serde_json::from_str(&line)?;

		if let Some(message) = value.get("error").and_then(Value::as_str) {
			return Err(HarnessError::CommandFailed { command: command.to_string(), message: message.to_string() });
		}

		Ok(value)
	}

	/// Stop the node and wait for the harness to exit.
	pub fn shutdown(mut self) -> Result<(), HarnessError> {
		self.request("shutdown", Value::Object(serde_json::Map::new()))?;
		self.child.wait()?;
		Ok(())
	}
}

impl Drop for E2eNode {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_harness_dir_is_inside_crate() {
		let dir = harness_dir();
		assert!(dir.ends_with("keetanetwork-utils/node-harness"));
		assert!(dir.join("package.json").exists());
	}

	#[test]
	fn test_dist_dir_resolves_or_reports_search_path() {
		match dist_dir() {
			Ok(dist) => assert!(dist.join("lib/block/index.js").exists()),
			Err(HarnessError::DistNotFound { searched }) => {
				assert!(searched.to_string_lossy().contains("keetanet-node"));
			}
			Err(error) => panic!("unexpected error variant: {error}"),
		}
	}
}
