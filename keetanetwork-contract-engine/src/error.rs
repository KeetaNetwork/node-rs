//! Engine errors.

use snafu::Snafu;

/// Everything that can make a call fail. Any error aborts the call and
/// rolls back all of its effects, unless a submessage with `reply_on`
/// error/always catches it.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum EngineError {
	/// The VM rejected the code or failed while running it.
	#[snafu(display("vm: {source}"))]
	Vm { source: cosmwasm_vm::VmError },

	/// The contract returned an error.
	#[snafu(display("contract: {message}"))]
	Contract { message: String },

	/// A ledger rule was violated (insufficient balance, not the token admin, …).
	#[snafu(display("ledger: {message}"))]
	Ledger { message: String },

	/// The contract used a message or query this host does not provide.
	#[snafu(display("unsupported: {what}"))]
	Unsupported { what: String },

	/// No contract exists at this address.
	#[snafu(display("no contract at {address}"))]
	UnknownContract { address: String },

	/// No code was stored under this id.
	#[snafu(display("no code with id {code_id}"))]
	UnknownCode { code_id: u64 },

	/// Not a valid Keeta address (or not of the required kind).
	#[snafu(display("invalid address {address}: {reason}"))]
	InvalidAddress { address: String, reason: String },

	/// A field would not pass Keeta block validation.
	#[snafu(display("invalid {field}: {reason}"))]
	InvalidField { field: &'static str, reason: String },

	/// The call ran out of gas.
	#[snafu(display("out of gas"))]
	OutOfGas,

	/// Contracts called each other too deeply.
	#[snafu(display("call depth limit of {limit} exceeded"))]
	DepthExceeded { limit: usize },

	/// Encoding or decoding a message failed.
	#[snafu(display("serialization: {message}"))]
	Serialization { message: String },

	/// The resulting operations did not form a valid Keeta block.
	#[snafu(display("block for {account}: {source}"))]
	Block { account: String, source: keetanetwork_block::BlockError },

	/// Could not set up the engine.
	#[snafu(display("setup: {message}"))]
	Setup { message: String },
}

impl From<cosmwasm_vm::VmError> for EngineError {
	fn from(source: cosmwasm_vm::VmError) -> Self {
		match source {
			cosmwasm_vm::VmError::GasDepletion { .. } => EngineError::OutOfGas,
			source => EngineError::Vm { source },
		}
	}
}

impl From<serde_json::Error> for EngineError {
	fn from(error: serde_json::Error) -> Self {
		EngineError::Serialization { message: error.to_string() }
	}
}

pub(crate) fn ledger(message: impl Into<String>) -> EngineError {
	EngineError::Ledger { message: message.into() }
}
