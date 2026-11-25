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
	/// The call's time: its order block's date, milliseconds since the Unix epoch
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

#[cfg(test)]
mod tests {
	use keetanetwork_contract_engine::HostError;
	use serde_json::json;

	use super::*;

	fn hex32(byte: u8) -> String {
		hex::encode([byte; 32])
	}

	#[test]
	fn the_config_fills_in_defaults() {
		let config: WireConfig = serde_json::from_value(json!({ "network": "21378" })).unwrap();
		let config = config.into_config();
		let defaults = EngineConfig::default();
		assert_eq!(config.network, 21378);
		assert_eq!(
			(config.max_call_depth, config.max_code_size, config.max_cached_code_size),
			(defaults.max_call_depth, defaults.max_code_size, defaults.max_cached_code_size)
		);

		let config: WireConfig = serde_json::from_value(
			json!({ "network": 1, "maxCallDepth": 2, "maxCodeSize": 3, "maxCachedCodeSize": 4 }),
		)
		.unwrap();
		let config = config.into_config();
		assert_eq!(
			(config.network, config.max_call_depth, config.max_code_size, config.max_cached_code_size),
			(1, 2, 3, 4)
		);

		assert!(serde_json::from_value::<WireConfig>(json!({ "network": 1, "extra": true })).is_err());
		assert!(serde_json::from_value::<WireConfig>(json!({ "network": "-1" })).is_err());
	}

	#[test]
	fn a_ledger_call_becomes_the_engines_call() {
		let call: WireLedgerCall = serde_json::from_value(json!({
			"caller": "keeta_caller",
			"instruction": {
				"contract": "keeta_contract",
				"accounts": [
					{ "owner": "keeta_contract", "id": hex32(1), "writable": true },
					{ "owner": "keeta_other", "id": hex32(2) }
				],
				"data": encode_b64(b"\x00\x01")
			},
			"funds": [{ "token": "keeta_token", "amount": "340282366920938463463374607431768211456" }],
			"gasLimit": "1400000",
			"timeMillis": 1_767_225_600_000i64
		}))
		.unwrap();
		let call = call.into_call().unwrap();
		assert_eq!(call.caller, "keeta_caller");
		assert_eq!(
			call.instruction,
			Instruction {
				contract: "keeta_contract".into(),
				accounts: vec![
					AccountMeta { owner: "keeta_contract".into(), id: [1; 32], writable: true },
					AccountMeta { owner: "keeta_other".into(), id: [2; 32], writable: false },
				],
				data: vec![0, 1],
			}
		);
		// Amounts may exceed a u128.
		assert_eq!(call.funds, vec![Fund::new("keeta_token", BigUint::from(u128::MAX) + 1u8)]);
		assert_eq!((call.gas_limit, call.time_millis), (1_400_000, 1_767_225_600_000));
	}

	#[test]
	fn a_ledger_call_takes_a_number_for_gas_and_needs_no_funds_or_accounts() {
		let call: WireLedgerCall = serde_json::from_value(json!({
			"caller": "keeta_caller",
			"instruction": { "contract": "keeta_contract", "data": "" },
			"gasLimit": 5,
			"timeMillis": 0
		}))
		.unwrap();
		let call = call.into_call().unwrap();
		assert_eq!((call.gas_limit, call.funds.len(), call.instruction.accounts.len()), (5, 0, 0));
	}

	#[test]
	fn malformed_calls_are_refused() {
		let call = |instruction: serde_json::Value, amount: &str| {
			serde_json::from_value::<WireLedgerCall>(json!({
				"caller": "keeta_caller",
				"instruction": instruction,
				"funds": [{ "token": "keeta_token", "amount": amount }],
				"gasLimit": "1",
				"timeMillis": 0
			}))
		};
		let good = json!({ "contract": "c", "data": "" });
		let error = call(json!({ "contract": "c", "data": "not base64!" }), "1")
			.err()
			.unwrap();
		assert!(error.to_string().contains("bad base64"), "{error}");
		let error = call(json!({ "contract": "c", "data": "", "accounts": [{ "owner": "c", "id": "zz" }] }), "1")
			.err()
			.unwrap();
		assert!(error.to_string().contains("bad hex"), "{error}");
		let error = call(json!({ "contract": "c", "data": "", "accounts": [{ "owner": "c", "id": "00" }] }), "1")
			.err()
			.unwrap();
		assert!(error.to_string().contains("expected 32 bytes of hex"), "{error}");
		assert!(call(json!({ "contract": "c", "data": "", "extra": 1 }), "1").is_err());

		let error = call(good, "-1").unwrap().into_call().err().unwrap();
		assert_eq!(error.to_string(), "bad amount \"-1\"");
		assert!(serde_json::from_value::<WireLedgerCall>(json!({
			"caller": "c", "instruction": { "contract": "c", "data": "" }, "gasLimit": "many", "timeMillis": 0
		}))
		.is_err());
	}

	#[test]
	fn host_requests_name_their_op() {
		let requests = [
			(HostRequest::CodeBytes { checksum: [0xab; 32] }, json!({ "op": "codeBytes", "checksum": hex32(0xab) })),
			(HostRequest::Contract { address: "a".into() }, json!({ "op": "contract", "address": "a" })),
			(
				HostRequest::StorageGet { contract: "c".into(), key: vec![1, 2] },
				json!({ "op": "storageGet", "contract": "c", "key": "AQI=" }),
			),
			(
				HostRequest::Balance { account: "a".into(), token: "t".into() },
				json!({ "op": "balance", "account": "a", "token": "t" }),
			),
			(HostRequest::TokenSupply { token: "t".into() }, json!({ "op": "tokenSupply", "token": "t" })),
			(
				HostRequest::SendRefusal { from: "f".into(), to: "t".into(), token: "k".into() },
				json!({ "op": "sendRefusal", "from": "f", "to": "t", "token": "k" }),
			),
		];
		for (request, expected) in requests {
			assert_eq!(request.op(), expected["op"]);
			assert_eq!(serde_json::to_value(&request).unwrap(), expected);
		}
	}

	#[test]
	fn a_contract_record_comes_from_the_host() {
		let record: WireContractRecord = serde_json::from_value(json!({
			"address": "keeta_contract",
			"codeHash": hex32(7),
			"info": { "name": "Pet", "description": "A pet", "metadata": "" }
		}))
		.unwrap();
		let record = ContractRecord::from(record);
		assert_eq!(record.code_hash, [7; 32]);
		assert_eq!(
			record.info,
			AccountInfo { name: "Pet".into(), description: "A pet".into(), metadata: String::new() }
		);
	}

	#[test]
	fn every_engine_error_has_a_stable_kind() {
		let message = || String::from("m");
		let errors = [
			(EngineError::Vm { message: message() }, "vm"),
			(EngineError::Contract { message: message() }, "contract"),
			(EngineError::Ledger { message: message() }, "ledger"),
			(EngineError::InvalidInstruction { reason: message() }, "invalidInstruction"),
			(EngineError::InvalidAccount { reason: message() }, "invalidAccount"),
			(EngineError::Reentrancy { contract: message() }, "reentrancy"),
			(EngineError::UnknownContract { address: message() }, "unknownContract"),
			(EngineError::InvalidAddress { address: message(), reason: message() }, "invalidAddress"),
			(EngineError::InvalidField { field: "name", reason: message() }, "invalidField"),
			(EngineError::OutOfGas, "outOfGas"),
			(EngineError::DepthExceeded { limit: 5 }, "depthExceeded"),
			(EngineError::Setup { message: message() }, "setup"),
			(EngineError::Host { source: HostError::new("down") }, "host"),
			(EngineError::CodeTooLarge { size: 2, limit: 1 }, "codeTooLarge"),
		];
		for (error, kind) in errors {
			let text = error.to_string();
			let json: serde_json::Value =
				serde_json::from_str(&Outcome::<()>::from_result(Err(error)).to_json()).unwrap();
			assert_eq!(json, json!({ "error": { "kind": kind, "message": text } }));
		}
		assert_eq!(Outcome::from_result(Ok("hash")).to_json(), r#"{"ok":"hash"}"#);
	}

	#[test]
	fn a_ledger_outcome_serializes_for_javascript() {
		let outcome = LedgerOutcome {
			data: Some(vec![1]),
			events: vec![Event { contract: "c".into(), attributes: vec![("action".into(), "feed".into())] }],
			logs: vec![Log { contract: "c".into(), message: "hello".into() }],
			gas_used: u64::MAX,
			reads: vec![StateAccess { owner: "c".into(), id: [1; 32], data: None }],
			writes: vec![StateAccess { owner: "c".into(), id: [2; 32], data: Some(vec![2, 3]) }],
			effects: vec![
				Effect::Send {
					from: "c".into(),
					to: "a".into(),
					token: "t".into(),
					amount: BigUint::from(u128::MAX) + 1u8,
					external: Some("memo".into()),
				},
				Effect::SetInfo {
					account: "c".into(),
					info: AccountInfo { name: "n".into(), description: "d".into(), metadata: "m".into() },
				},
			],
		};
		let json = serde_json::to_value(Outcome::Ok(WireLedgerOutcome::from(outcome))).unwrap();
		assert_eq!(
			json,
			json!({ "ok": {
				"data": "AQ==",
				"events": [{ "contract": "c", "attributes": [["action", "feed"]] }],
				"logs": [{ "contract": "c", "message": "hello" }],
				// As text: JavaScript numbers cannot hold every u64.
				"gasUsed": u64::MAX.to_string(),
				"reads": [{ "owner": "c", "id": hex32(1), "data": null }],
				"writes": [{ "owner": "c", "id": hex32(2), "data": "AgM=" }],
				"effects": [
					{ "kind": "send", "from": "c", "to": "a", "token": "t", "amount": "340282366920938463463374607431768211456", "external": "memo" },
					{ "kind": "setInfo", "account": "c", "name": "n", "description": "d", "metadata": "m" }
				]
			}})
		);
		let empty = LedgerOutcome {
			data: None,
			events: vec![],
			logs: vec![],
			gas_used: 0,
			reads: vec![],
			writes: vec![],
			effects: vec![],
		};
		assert_eq!(serde_json::to_value(WireLedgerOutcome::from(empty)).unwrap()["data"], json!(null));
	}

	#[test]
	fn wire_errors_show_their_message() {
		assert_eq!(WireError("bad".into()).to_string(), "bad");
		assert_eq!(decode_b64("AQI=").unwrap(), vec![1, 2]);
		assert_eq!(decode_hash(&hex32(9)).unwrap(), [9; 32]);
	}
}
