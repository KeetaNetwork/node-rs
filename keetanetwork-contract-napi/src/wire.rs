//! The JSON shapes that cross between JavaScript and the engine.
//!
//! Conventions: field names are camelCase; byte strings are base64;
//! hashes are lowercase hex; `u64` values are decimal strings (plain numbers
//! are accepted on input), so JavaScript never loses precision.

use keetanetwork_contract_engine::{
	AccountInfo, AccountMeta, ContractRecord, Effect, EngineConfig, EngineError, Event, Fund, Instruction, LedgerCall,
	LedgerOutcome, Log, StateAccess,
};
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A wire-format problem: bad JSON, base64, hex or number.
#[derive(Debug)]
pub struct WireError(pub String);

impl std::fmt::Display for WireError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

pub type WireResult<T> = Result<T, WireError>;

fn wire_error(what: impl std::fmt::Display) -> WireError {
	WireError(what.to_string())
}

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub fn encode_b64(bytes: &[u8]) -> String {
	base64::Engine::encode(&BASE64, bytes)
}

pub fn decode_b64(text: &str) -> WireResult<Vec<u8>> {
	base64::Engine::decode(&BASE64, text).map_err(|error| wire_error(format!("bad base64: {error}")))
}

pub fn decode_hash(text: &str) -> WireResult<[u8; 32]> {
	let bytes = hex::decode(text).map_err(|error| wire_error(format!("bad hex: {error}")))?;
	bytes
		.try_into()
		.map_err(|_| wire_error("expected 32 bytes of hex"))
}

/// Serde helpers for the conventions above.
pub mod codec {
	use super::*;

	pub mod b64 {
		use super::*;

		pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
			serializer.serialize_str(&encode_b64(bytes))
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
			let text = String::deserialize(deserializer)?;
			decode_b64(&text).map_err(serde::de::Error::custom)
		}
	}

	pub mod b64_option {
		use super::*;

		pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
			match bytes {
				Some(bytes) => serializer.serialize_some(&encode_b64(bytes)),
				None => serializer.serialize_none(),
			}
		}
	}

	pub mod hash {
		use super::*;

		pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
			serializer.serialize_str(&hex::encode(bytes))
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
			let text = String::deserialize(deserializer)?;
			decode_hash(&text).map_err(serde::de::Error::custom)
		}
	}

	/// A `u64` written as a decimal string, read from a string or a number.
	pub mod u64_text {
		use super::*;

		#[derive(Deserialize)]
		#[serde(untagged)]
		enum Either {
			Number(u64),
			Text(String),
		}

		pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
			serializer.serialize_str(&value.to_string())
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
			match Either::deserialize(deserializer)? {
				Either::Number(value) => Ok(value),
				Either::Text(text) => text.parse().map_err(serde::de::Error::custom),
			}
		}
	}
}

use codec::{b64, b64_option, hash, u64_text};

// ---------------------------------------------------------------------------
// Configuration and calls
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireConfig {
	/// Keeta network id
	#[serde(with = "u64_text")]
	pub network: u64,
	/// How many contracts may run at once (one call and its invocations)
	pub max_call_depth: Option<usize>,
	/// The largest code `storeCode` accepts, in bytes
	pub max_code_size: Option<usize>,
	/// How much loaded code to keep between calls, in bytes
	pub max_cached_code_size: Option<usize>,
}

impl WireConfig {
	pub fn into_config(self) -> EngineConfig {
		let defaults = EngineConfig::default();
		EngineConfig {
			network: self.network,
			max_call_depth: self.max_call_depth.unwrap_or(defaults.max_call_depth),
			max_code_size: self.max_code_size.unwrap_or(defaults.max_code_size),
			max_cached_code_size: self
				.max_cached_code_size
				.unwrap_or(defaults.max_cached_code_size),
		}
	}
}

/// An account an instruction touches.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireAccountMeta {
	/// The contract whose state it is
	pub owner: String,
	/// Its 32-byte id, hex
	#[serde(with = "hash")]
	pub id: [u8; 32],
	#[serde(default)]
	pub writable: bool,
}

/// What a call runs: `{ contract, accounts, data }`, data in base64.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireInstruction {
	pub contract: String,
	#[serde(default)]
	pub accounts: Vec<WireAccountMeta>,
	#[serde(with = "b64")]
	pub data: Vec<u8>,
}

impl From<WireInstruction> for Instruction {
	fn from(instruction: WireInstruction) -> Self {
		Instruction {
			contract: instruction.contract,
			accounts: instruction
				.accounts
				.into_iter()
				.map(|meta| AccountMeta { owner: meta.owner, id: meta.id, writable: meta.writable })
				.collect(),
			data: instruction.data,
		}
	}
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireFund {
	pub token: String,
	/// Decimal
	pub amount: String,
}

/// A call carried by a block on the ledger.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireLedgerCall {
	/// The account whose block carries the call
	pub caller: String,
	pub instruction: WireInstruction,
	/// Tokens the block sends to the contract before the call
	#[serde(default)]
	pub funds: Vec<WireFund>,
	#[serde(with = "u64_text")]
	pub gas_limit: u64,
	/// The block's time, milliseconds since the Unix epoch
	pub time_millis: i64,
}

impl WireLedgerCall {
	pub fn into_call(self) -> WireResult<LedgerCall> {
		let funds = self
			.funds
			.into_iter()
			.map(|fund| {
				let amount: BigUint = fund
					.amount
					.parse()
					.map_err(|_| wire_error(format!("bad amount {:?}", fund.amount)))?;
				Ok(Fund::new(fund.token, amount))
			})
			.collect::<WireResult<Vec<_>>>()?;
		Ok(LedgerCall {
			caller: self.caller,
			instruction: self.instruction.into(),
			funds,
			gas_limit: self.gas_limit,
			time_millis: self.time_millis,
		})
	}
}

// ---------------------------------------------------------------------------
// Host requests
// ---------------------------------------------------------------------------

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireAccountInfo {
	pub name: String,
	pub description: String,
	pub metadata: String,
}

/// A deployed contract, as the host describes it.
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireContractRecord {
	pub address: String,
	/// SHA-256 of its code, hex
	#[serde(with = "hash")]
	pub code_hash: [u8; 32],
	pub info: WireAccountInfo,
}

impl From<WireContractRecord> for ContractRecord {
	fn from(record: WireContractRecord) -> Self {
		let WireAccountInfo { name, description, metadata } = record.info;
		Self { code_hash: record.code_hash, info: AccountInfo { name, description, metadata } }
	}
}

/// What the engine asks the JavaScript host. The host answers with the
/// JSON of the value described on each variant.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum HostRequest {
	/// → base64 ELF `| null`
	CodeBytes {
		#[serde(with = "hash")]
		checksum: [u8; 32],
	},
	/// → `WireContractRecord | null`
	Contract { address: String },
	/// → base64 account data `| null`; `key` is the account's 32-byte id
	StorageGet {
		contract: String,
		#[serde(with = "b64")]
		key: Vec<u8>,
	},
	/// → decimal string
	Balance { account: String, token: String },
	/// → decimal string `| null` (null if the token does not exist)
	TokenSupply { token: String },
	/// → why the ledger would refuse a `SEND` of `token` from `from` to
	/// `to` (a missing permission) `| null` if it would accept one
	SendRefusal { from: String, to: String, token: String },
}

impl HostRequest {
	pub fn op(&self) -> &'static str {
		match self {
			HostRequest::CodeBytes { .. } => "codeBytes",
			HostRequest::Contract { .. } => "contract",
			HostRequest::StorageGet { .. } => "storageGet",
			HostRequest::Balance { .. } => "balance",
			HostRequest::TokenSupply { .. } => "tokenSupply",
			HostRequest::SendRefusal { .. } => "sendRefusal",
		}
	}
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// What every engine call resolves to.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome<T: Serialize> {
	Ok(T),
	Error { kind: &'static str, message: String },
}

impl<T: Serialize> Outcome<T> {
	pub fn from_result(result: Result<T, EngineError>) -> Self {
		match result {
			Ok(value) => Outcome::Ok(value),
			Err(error) => Outcome::Error { kind: error_kind(&error), message: error.to_string() },
		}
	}

	pub fn to_json(&self) -> String {
		serde_json::to_string(self).expect("outcomes serialize")
	}
}

/// A stable name for each engine error, for callers to branch on.
pub fn error_kind(error: &EngineError) -> &'static str {
	match error {
		EngineError::Vm { .. } => "vm",
		EngineError::Contract { .. } => "contract",
		EngineError::Ledger { .. } => "ledger",
		EngineError::InvalidInstruction { .. } => "invalidInstruction",
		EngineError::InvalidAccount { .. } => "invalidAccount",
		EngineError::Reentrancy { .. } => "reentrancy",
		EngineError::UnknownContract { .. } => "unknownContract",
		EngineError::InvalidAddress { .. } => "invalidAddress",
		EngineError::InvalidField { .. } => "invalidField",
		EngineError::OutOfGas => "outOfGas",
		EngineError::DepthExceeded { .. } => "depthExceeded",
		EngineError::Setup { .. } => "setup",
		EngineError::Host { .. } => "host",
		EngineError::CodeTooLarge { .. } => "codeTooLarge",
	}
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireEvent {
	pub contract: String,
	pub attributes: Vec<(String, String)>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireLog {
	pub contract: String,
	pub message: String,
}

/// A state account a call read or wrote.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireStateAccess {
	pub owner: String,
	#[serde(with = "hash")]
	pub id: [u8; 32],
	/// New data for a write (`null` deletes), the data read for a read
	#[serde(with = "b64_option")]
	pub data: Option<Vec<u8>>,
}

/// A ledger effect of a call.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum WireLedgerEffect {
	/// `SEND` from a contract
	Send { from: String, to: String, token: String, amount: String, external: Option<String> },
	/// `SET_INFO` on a contract
	SetInfo { account: String, name: String, description: String, metadata: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireLedgerOutcome {
	#[serde(with = "b64_option")]
	pub data: Option<Vec<u8>>,
	pub events: Vec<WireEvent>,
	pub logs: Vec<WireLog>,
	#[serde(with = "u64_text")]
	pub gas_used: u64,
	pub reads: Vec<WireStateAccess>,
	pub writes: Vec<WireStateAccess>,
	pub effects: Vec<WireLedgerEffect>,
}

impl From<LedgerOutcome> for WireLedgerOutcome {
	fn from(outcome: LedgerOutcome) -> Self {
		let access = |access: StateAccess| WireStateAccess { owner: access.owner, id: access.id, data: access.data };
		Self {
			data: outcome.data,
			events: outcome
				.events
				.into_iter()
				.map(|Event { contract, attributes }| WireEvent { contract, attributes })
				.collect(),
			logs: outcome
				.logs
				.into_iter()
				.map(|Log { contract, message }| WireLog { contract, message })
				.collect(),
			gas_used: outcome.gas_used,
			reads: outcome.reads.into_iter().map(&access).collect(),
			writes: outcome.writes.into_iter().map(&access).collect(),
			effects: outcome
				.effects
				.into_iter()
				.map(|effect| match effect {
					Effect::Send { from, to, token, amount, external } => {
						WireLedgerEffect::Send { from, to, token, amount: amount.to_string(), external }
					}
					Effect::SetInfo { account, info } => WireLedgerEffect::SetInfo {
						account,
						name: info.name,
						description: info.description,
						metadata: info.metadata,
					},
				})
				.collect(),
		}
	}
}
