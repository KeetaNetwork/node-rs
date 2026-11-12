//! Engine errors.

use snafu::Snafu;

/// Everything that can make a call fail. Any error aborts the whole call
/// and undoes all of its effects: as on Solana, a failure anywhere (in any
/// contract, or in a host function a contract called) is never caught.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum EngineError {
	/// The VM refused the code, or the contract faulted (bad memory access,
	/// division by zero, …).
	#[snafu(display("vm: {message}"))]
	Vm { message: String },

	/// The contract returned an error or panicked.
	#[snafu(display("contract: {message}"))]
	Contract { message: String },

	/// A ledger rule was violated (insufficient balance, a `SEND` the ledger's
	/// permissions refuse, …).
	#[snafu(display("ledger: {message}"))]
	Ledger { message: String },

	/// The instruction is malformed: too many accounts, a duplicate account,
	/// too much data, …
	#[snafu(display("invalid instruction: {reason}"))]
	InvalidInstruction { reason: String },

	/// A contract changed an account it may not, or grew one too far.
	#[snafu(display("invalid account change: {reason}"))]
	InvalidAccount { reason: String },

	/// No contract exists at this address.
	#[snafu(display("no contract at {address}"))]
	UnknownContract { address: String },

	/// Not a valid Keeta address (or not of the required kind).
	#[snafu(display("invalid address {address}: {reason}"))]
	InvalidAddress { address: String, reason: String },

	/// A field would not pass Keeta block validation.
	#[snafu(display("invalid {field}: {reason}"))]
	InvalidField { field: &'static str, reason: String },

	/// The call ran out of gas.
	#[snafu(display("out of gas"))]
	OutOfGas,

	/// Contracts invoked each other too deeply.
	#[snafu(display("call depth limit of {limit} exceeded"))]
	DepthExceeded { limit: usize },

	/// A contract was invoked while it was already running.
	#[snafu(display("{contract} is already running in this call and cannot be re-entered"))]
	Reentrancy { contract: String },

	/// Could not set up the engine.
	#[snafu(display("setup: {message}"))]
	Setup { message: String },

	/// The host could not answer a read.
	#[snafu(display("host: {source}"))]
	Host { source: crate::host::HostError },

	/// The code is larger than [`EngineConfig::max_code_size`].
	///
	/// [`EngineConfig::max_code_size`]: crate::EngineConfig::max_code_size
	#[snafu(display("code is {size} bytes, more than the {limit}-byte limit"))]
	CodeTooLarge { size: usize, limit: usize },
}

impl From<crate::host::HostError> for EngineError {
	fn from(source: crate::host::HostError) -> Self {
		EngineError::Host { source }
	}
}

pub(crate) fn ledger(message: impl Into<String>) -> EngineError {
	EngineError::Ledger { message: message.into() }
}
