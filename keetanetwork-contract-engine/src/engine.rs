//! The engine: checks code, and runs contract calls for the ledger.
//!
//! Execution model (Solana's):
//!
//! - A call runs one [`Instruction`]: a contract, the accounts it touches
//!   (each read-only or writable) and raw instruction data. Contracts can
//!   invoke each other, passing on accounts from that list.
//! - A contract can read every account it is given, but change only its
//!   own writable ones.
//! - Everything is atomic: if any contract or host function fails, the whole
//!   call fails and nothing it did remains.
//! - Gas, in compute units, is shared by the whole call.
//!
//! The engine holds no ledger or contract state between calls: it reads
//! through a [`Host`] and returns what the call read, wrote and did.

use std::sync::Arc;

use keetanetwork_account::KeyPairType;
use keetanetwork_contract_std::StateId;
use num_bigint::BigUint;

use crate::address::{parse_account, parse_account_of};
use crate::error::EngineError;
use crate::host::{AccountInfo, CodeHash, Host};
use crate::vm::{self, Core, Request, Session};

/// The largest code [`Engine::store_code`] accepts by default, in bytes:
/// the same as the node's limit on `CONTRACT_DEPLOY` code.
pub const DEFAULT_MAX_CODE_SIZE: usize = 512 * 1024;

/// How much loaded code the engine keeps by default, in bytes of ELF: at
/// least 128 contracts at the largest size [`DEFAULT_MAX_CODE_SIZE`] allows.
pub const DEFAULT_MAX_CACHED_CODE_SIZE: usize = 64 * 1024 * 1024;

/// Engine settings.
#[derive(Clone, Debug)]
pub struct EngineConfig {
	/// Keeta network id, which sets the field rules contract output is held to
	pub network: u64,
	/// How many contracts may be running at once: the top-level one and
	/// those it invokes, directly or not
	pub max_call_depth: usize,
	/// The largest ELF file [`Engine::store_code`] accepts, in bytes.
	/// Checked only when code is stored, so lowering it leaves code already
	/// stored running.
	pub max_code_size: usize,
	/// How much loaded code to keep between calls, in bytes of ELF. Past
	/// it, the code used least recently is dropped and loaded from the host
	/// again when next called; code larger than this is never kept.
	pub max_cached_code_size: usize,
}

impl Default for EngineConfig {
	/// A local test network's settings.
	fn default() -> Self {
		Self {
			network: 0,
			max_call_depth: 5,
			max_code_size: DEFAULT_MAX_CODE_SIZE,
			max_cached_code_size: DEFAULT_MAX_CACHED_CODE_SIZE,
		}
	}
}

/// An account in an instruction: a piece of `owner`'s state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
	/// The contract whose state it is
	pub owner: String,
	/// Its id within that contract's state
	pub id: StateId,
	/// Whether the call may change it
	pub writable: bool,
}

impl AccountMeta {
	/// A writable account.
	pub fn writable(owner: impl Into<String>, id: StateId) -> Self {
		Self { owner: owner.into(), id, writable: true }
	}

	/// A read-only account.
	pub fn readonly(owner: impl Into<String>, id: StateId) -> Self {
		Self { owner: owner.into(), id, writable: false }
	}
}

/// What a call runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
	/// Contract to run
	pub contract: String,
	/// Every account the call touches, including those of contracts it
	/// invokes
	pub accounts: Vec<AccountMeta>,
	/// Instruction data, in whatever encoding the contract uses
	pub data: Vec<u8>,
}

impl Instruction {
	/// Run `contract` with `accounts` and `data`.
	pub fn new(contract: impl Into<String>, accounts: Vec<AccountMeta>, data: impl Into<Vec<u8>>) -> Self {
		Self { contract: contract.into(), accounts, data: data.into() }
	}
}

/// Tokens attached to a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fund {
	/// Token address
	pub token: String,
	/// Amount
	pub amount: BigUint,
}

impl Fund {
	/// Attach `amount` of `token`.
	pub fn new(token: impl Into<String>, amount: impl Into<BigUint>) -> Self {
		Self { token: token.into(), amount: amount.into() }
	}
}

/// What one contract invocation reported with [`keetanetwork_contract_std::attribute`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
	/// The contract that ran
	pub contract: String,
	/// Key-value attributes, in order
	pub attributes: Vec<(String, String)>,
}

/// A log line from a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
	/// Contract that logged it
	pub contract: String,
	/// The line
	pub message: String,
}

/// A contract call, as a block on the ledger carries it.
#[derive(Clone, Debug)]
pub struct LedgerCall {
	/// The account whose block carries the call: the contract's caller
	pub caller: String,
	/// The instruction
	pub instruction: Instruction,
	/// Tokens the caller's block sends to the contract before the call. The
	/// block's own `SEND`s move them; the engine only lets the contract see
	/// them in its balance and its `funds`.
	pub funds: Vec<Fund>,
	/// Gas for the call
	pub gas_limit: u64,
	/// The block's time in milliseconds since the Unix epoch: the same for
	/// every representative
	pub time_millis: i64,
}

/// An account a call read, or wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateAccess {
	/// The contract whose state it is
	pub owner: String,
	/// Its id
	pub id: StateId,
	/// For a write, the new data (`None` deletes the account); for a read,
	/// the data it had
	pub data: Option<Vec<u8>>,
}

/// One ledger effect of a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
	/// `SEND` from a contract.
	Send { from: String, to: String, token: String, amount: BigUint, external: Option<String> },
	/// `SET_INFO` on a contract.
	SetInfo { account: String, info: AccountInfo },
}

/// What a call does, for a representative to check, vote on and apply.
#[derive(Debug)]
pub struct LedgerOutcome {
	/// Data returned by the contract
	pub data: Option<Vec<u8>>,
	/// One event per invocation, outermost first
	pub events: Vec<Event>,
	/// Log lines, in order
	pub logs: Vec<Log>,
	/// Gas used, in compute units
	pub gas_used: u64,
	/// Every state account the call read, in (owner, id) order
	pub reads: Vec<StateAccess>,
	/// Every state account the call changed, in (owner, id) order
	pub writes: Vec<StateAccess>,
	/// Ledger effects, in order: `SEND`s from contracts, then a `SET_INFO`
	/// for each contract whose info changed. The call's funds are not among
	/// them: the caller's block moves those itself.
	pub effects: Vec<Effect>,
}

impl LedgerOutcome {
	/// The first value of attribute `key` across all events.
	pub fn attribute(&self, key: &str) -> Option<&str> {
		self.events
			.iter()
			.flat_map(|event| &event.attributes)
			.find(|(k, _)| k == key)
			.map(|(_, value)| value.as_str())
	}
}

/// An sBPF contract engine for Keeta.
pub struct Engine {
	core: Arc<Core>,
}

impl Engine {
	/// An engine with the given settings.
	pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
		Ok(Self { core: Arc::new(Core::new(config)?) })
	}

	/// Engine settings.
	pub fn config(&self) -> &EngineConfig {
		&self.core.config
	}

	/// Check sBPF v3 code and keep it loaded, within
	/// [`EngineConfig::max_cached_code_size`]. Returns its hash.
	///
	/// Code larger than [`EngineConfig::max_code_size`] is refused before it
	/// is parsed. The loader parses the ELF file and the verifier checks
	/// every instruction, including that the code calls only host functions
	/// this engine provides.
	pub fn store_code(&self, elf: &[u8]) -> Result<CodeHash, EngineError> {
		self.core.store(elf)
	}

	/// Run a call against the ledger's state, through `host`. Returns what
	/// the call read, what it wrote and its ledger effects, and changes
	/// nothing.
	pub fn run_ledger_call(&self, host: Arc<dyn Host>, call: &LedgerCall) -> Result<LedgerOutcome, EngineError> {
		parse_account(&call.caller)?;
		let session = Arc::new(Session::new(self.core.clone(), host, call.time_millis));
		let contract = &call.instruction.contract;
		{
			let host = session.host();
			let mut overlay = session.lock();
			overlay.contract(host, contract)?;
			for fund in &call.funds {
				parse_account_of(&fund.token, KeyPairType::TOKEN)?;
				// The block's own `SEND`s move the funds: the call sees them
				// gone from the caller and held by the contract.
				overlay.debit(host, &call.caller, &fund.token, &fund.amount)?;
				overlay.credit(host, contract, &fund.token, &fund.amount)?;
			}
		}

		let outcome = vm::invoke(
			&session,
			Request {
				contract,
				caller: &call.caller,
				funds: &call.funds,
				accounts: &call.instruction.accounts,
				room: &[],
				data: &call.instruction.data,
			},
			call.gas_limit,
		)?;

		let mut overlay = session.lock();
		let reads = overlay
			.storage_reads()
			.into_iter()
			.map(|(owner, key, data)| state_access(owner, &key, data))
			.collect::<Result<Vec<_>, _>>()?;
		let writes = overlay
			.storage_writes()
			.into_iter()
			.map(|((owner, key), data)| state_access(owner, &key, data))
			.collect::<Result<Vec<_>, _>>()?;
		let mut effects = std::mem::take(&mut overlay.effects);
		effects.extend(
			overlay
				.changed_infos()
				.into_iter()
				.map(|(account, info)| Effect::SetInfo { account, info }),
		);
		drop(overlay);

		let events = std::mem::take(&mut *session.events.lock().expect("events lock"));
		let logs = std::mem::take(&mut *session.logs.lock().expect("logs lock"));
		Ok(LedgerOutcome {
			data: outcome.return_data,
			events,
			logs,
			gas_used: call.gas_limit - outcome.remaining,
			reads,
			writes,
			effects,
		})
	}
}

fn state_access(owner: String, key: &[u8], data: Option<Vec<u8>>) -> Result<StateAccess, EngineError> {
	let id = key
		.try_into()
		.map_err(|_| EngineError::Setup { message: format!("{owner} has a storage key that is not an account id") })?;
	Ok(StateAccess { owner, id, data })
}
