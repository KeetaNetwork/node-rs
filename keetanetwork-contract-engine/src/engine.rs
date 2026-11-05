//! The engine: stores code, runs calls, dispatches the messages contracts
//! emit, and turns committed calls into Keeta blocks.
//!
//! Execution model (the same as CosmWasm's, so existing contracts behave
//! as their authors expect):
//!
//! - A call runs the contract, then each message in its response in order,
//!   depth first. Messages to other contracts are calls in their own right.
//! - Everything is atomic: if anything fails, the whole call is rolled
//!   back, unless a submessage with `reply_on` error/always catches the
//!   failure, in which case only that submessage is rolled back and the
//!   emitting contract's `reply` decides what happens next.
//! - Gas is shared by the whole call. Running out is never recoverable,
//!   except within a submessage that set its own gas limit.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use cosmwasm_std::{BankMsg, Binary, ContractResult, CosmosMsg, ReplyOn, Response, SubMsg, WasmMsg};
use cosmwasm_vm::{
	call_execute_raw, call_instantiate_raw, call_query_raw, call_reply_raw, AnalysisReport, Cache, CacheOptions, Size,
	VmResult,
};
use keetanetwork_account::KeyPairType;
use keetanetwork_block::{AccountRef, TextRule, UnsignedBlock, ValidationConfig};
use keetanetwork_contract_std::{KeetaAmount, KeetaMsg};
use num_bigint::{BigInt, BigUint};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::address::{parse_account, parse_account_of};
use crate::backend::{gas_used, BlockContext, KeetaInstance, Shared};
use crate::error::{ledger, EngineError};
use crate::output::build_blocks;
use crate::state::{AccountInfo, ChainState, CodeRecord, ContractRecord, LedgerOp, TokenRecord};

/// Capabilities this host advertises by default. Contracts requiring
/// anything else are rejected when their code is stored.
///
/// The `cosmwasm_*` versions are advertised because the cw-plus ecosystem
/// enables them; the few features behind them that the spike does not
/// implement (distribution queries, `Instantiate2`, `Any` messages, denom
/// metadata) fail at runtime with [`EngineError::Unsupported`].
pub const CAPABILITIES: &[&str] = &[
	"iterator",
	"cosmwasm_1_1",
	"cosmwasm_1_2",
	"cosmwasm_1_3",
	"cosmwasm_1_4",
	"cosmwasm_2_0",
	"cosmwasm_2_1",
	"cosmwasm_2_2",
	keetanetwork_contract_std::CAPABILITY,
];

/// Gas for a call that does not specify a limit, in CosmWasm gas.
pub const DEFAULT_GAS_LIMIT: u64 = 50_000_000_000;

/// Gas for top-level queries, in CosmWasm gas.
pub const QUERY_GAS_LIMIT: u64 = 10_000_000_000;

/// Engine settings.
#[derive(Clone, Debug)]
pub struct EngineConfig {
	/// Keeta network id the blocks are built for
	pub network: u64,
	/// `env.block.chain_id` as contracts see it
	pub chain_id: String,
	/// The sequencer account: owns contract and token accounts and signs
	/// their blocks
	pub sequencer: AccountRef,
	/// How deeply contracts may call (or smart-query) each other
	pub max_call_depth: usize,
	/// Memory limit per contract instance
	pub instance_memory_limit: Size,
	/// Capabilities offered to contracts (defaults to [`CAPABILITIES`])
	pub capabilities: HashSet<String>,
}

impl EngineConfig {
	/// Defaults for a local test network.
	pub fn new(sequencer: AccountRef) -> Self {
		Self {
			network: 0,
			chain_id: "keeta-local".into(),
			sequencer,
			max_call_depth: 10,
			instance_memory_limit: Size::mebi(32),
			capabilities: CAPABILITIES.iter().map(|c| c.to_string()).collect(),
		}
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

/// Who is calling, with what, and when.
#[derive(Clone, Debug)]
pub struct Call {
	/// Calling account
	pub sender: String,
	/// Tokens moved from the sender to the contract before it runs
	pub funds: Vec<Fund>,
	/// Gas for the whole call, including nested calls
	pub gas_limit: u64,
	/// Height and time the call executes at
	pub block: BlockContext,
}

impl Call {
	/// A call from `sender` at `block`, with no funds and the default gas limit.
	pub fn new(sender: impl Into<String>, block: BlockContext) -> Self {
		Self { sender: sender.into(), funds: Vec::new(), gas_limit: DEFAULT_GAS_LIMIT, block }
	}

	/// Attach tokens.
	pub fn with_funds(mut self, funds: impl IntoIterator<Item = Fund>) -> Self {
		self.funds.extend(funds);
		self
	}

	/// Set the gas limit.
	pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
		self.gas_limit = gas_limit;
		self
	}
}

/// A contract or host event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
	/// Event type (`execute`, `wasm`, `wasm-<custom>`, …)
	pub ty: String,
	/// Key-value attributes
	pub attributes: Vec<(String, String)>,
}

/// The result of a committed call.
#[derive(Debug)]
pub struct Execution {
	/// The contract called (or, for instantiation, created)
	pub contract: String,
	/// Data returned by the contract
	pub data: Option<Vec<u8>>,
	/// Events, in emission order
	pub events: Vec<Event>,
	/// Gas used by the whole call, in CosmWasm gas
	pub gas_used: u64,
	/// Ledger effects, in order
	pub operations: Vec<LedgerOp>,
	/// The Keeta blocks those effects become: what the sequencer publishes
	/// as one vote staple
	pub blocks: Vec<UnsignedBlock>,
	/// State root after the call
	pub state_root: [u8; 32],
}

impl Execution {
	/// The first value of attribute `key` across all events.
	pub fn attribute(&self, key: &str) -> Option<&str> {
		self.events
			.iter()
			.flat_map(|event| &event.attributes)
			.find(|(k, _)| k == key)
			.map(|(_, value)| value.as_str())
	}
}

/// Lets the engine parse `Response<KeetaMsg>` with cosmwasm-std 3 types
/// while `KeetaMsg` itself stays free of cosmwasm-std.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(transparent)]
struct KeetaMsgWire(KeetaMsg);

impl cosmwasm_std::CustomMsg for KeetaMsgWire {}

/// A CosmWasm-compatible contract engine over an in-memory Keeta ledger.
pub struct Engine {
	shared: Arc<Shared>,
	_cache_dir: tempfile::TempDir,
}

impl Engine {
	/// An engine with empty state.
	pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
		let cache_dir = tempfile::tempdir().map_err(|error| EngineError::Setup { message: error.to_string() })?;
		let options = CacheOptions::new(
			cache_dir.path(),
			config.capabilities.clone(),
			Size::mebi(64),
			config.instance_memory_limit,
		);
		// SAFETY: `Cache::new` trusts compiled artifacts already in its
		// directory. This one is a fresh temp dir owned by this engine, so it
		// only ever holds artifacts the engine itself compiled.
		#[allow(unsafe_code)]
		let cache = unsafe { Cache::new(options) }?;

		Ok(Self {
			shared: Arc::new(Shared { cache, state: Mutex::new(ChainState::default()), config }),
			_cache_dir: cache_dir,
		})
	}

	/// Engine settings.
	pub fn config(&self) -> &EngineConfig {
		&self.shared.config
	}

	/// Validate, compile and store Wasm code. Returns its code id.
	///
	/// Validation is CosmWasm's static analysis: well-formed module, only
	/// known imports, required exports, size and memory limits, and
	/// required capabilities this host provides.
	pub fn store_code(&self, wasm: &[u8]) -> Result<u64, EngineError> {
		let checksum = self.shared.cache.store_code(wasm, true, true)?;
		let mut state = self.shared.lock();
		state.codes.push(CodeRecord { checksum });
		Ok(state.codes.len() as u64)
	}

	/// What static analysis found in stored code (entry points, required
	/// capabilities, …).
	pub fn analyze(&self, code_id: u64) -> Result<AnalysisReport, EngineError> {
		let checksum = self.shared.lock().checksum_of(code_id)?;
		Ok(self.shared.cache.analyze(&checksum)?)
	}

	/// Create a contract from `code_id` and run its `instantiate`.
	pub fn instantiate<M: Serialize>(
		&self,
		call: &Call,
		code_id: u64,
		msg: &M,
		label: &str,
	) -> Result<Execution, EngineError> {
		let msg = serde_json::to_vec(msg)?;
		self.transact(call, |tx| {
			let contract = tx.create_contract(code_id, &call.sender, None, label)?;
			let outcome = tx.call_contract(Entry::Instantiate, &contract, &call.sender, &call.funds, &msg)?;
			Ok((contract, outcome))
		})
	}

	/// Run `contract`'s `execute`.
	pub fn execute<M: Serialize>(&self, call: &Call, contract: &str, msg: &M) -> Result<Execution, EngineError> {
		let msg = serde_json::to_vec(msg)?;
		self.transact(call, |tx| {
			let outcome = tx.call_contract(Entry::Execute, contract, &call.sender, &call.funds, &msg)?;
			Ok((contract.to_string(), outcome))
		})
	}

	/// Run `contract`'s `query`. Read-only: never changes state.
	pub fn query<M: Serialize, R: DeserializeOwned>(
		&self,
		block: BlockContext,
		contract: &str,
		msg: &M,
	) -> Result<R, EngineError> {
		let msg = serde_json::to_vec(msg)?;
		let mut instance = self.shared.instance(contract, block, 0, QUERY_GAS_LIMIT)?;
		let env = self.shared.env(&block, contract);
		let raw = call_query_raw(&mut instance, &env, &msg)?;
		let result: ContractResult<Binary> = serde_json::from_slice(&raw)?;
		let data = result
			.into_result()
			.map_err(|message| EngineError::Contract { message })?;
		Ok(serde_json::from_slice(data.as_slice())?)
	}

	/// Credit tokens outside of any call (genesis / test setup).
	pub fn credit_genesis(&self, account: &str, token: &str, amount: impl Into<BigUint>) -> Result<(), EngineError> {
		parse_account(account)?;
		parse_account_of(token, KeyPairType::TOKEN)?;
		self.shared.lock().credit(account, token, &amount.into());
		Ok(())
	}

	/// An account's balance of a token.
	pub fn balance(&self, account: &str, token: &str) -> BigUint {
		self.shared.lock().balance(account, token)
	}

	/// An account's `SET_INFO` fields.
	pub fn account_info(&self, account: &str) -> AccountInfo {
		self.shared
			.lock()
			.accounts
			.get(account)
			.cloned()
			.unwrap_or_default()
	}

	/// The token `creator` issued under `subdenom`, if any.
	pub fn token_address(&self, creator: &str, subdenom: &str) -> Option<String> {
		self.shared
			.lock()
			.token_registry
			.get(&(creator.to_string(), subdenom.to_string()))
			.cloned()
	}

	/// A token's total supply.
	pub fn token_supply(&self, token: &str) -> Option<BigUint> {
		self.shared
			.lock()
			.tokens
			.get(token)
			.map(|token| token.supply.clone())
	}

	/// Commitment to the current state.
	pub fn state_root(&self) -> [u8; 32] {
		self.shared.lock().state_root()
	}

	/// Run a call atomically: commit and build blocks on success, restore
	/// the previous state on any failure.
	fn transact(
		&self,
		call: &Call,
		run: impl FnOnce(&mut Tx<'_>) -> Result<(String, Outcome), EngineError>,
	) -> Result<Execution, EngineError> {
		let checkpoint = self.shared.lock().clone();
		let mut tx = Tx { shared: &self.shared, block: call.block, gas_limit: call.gas_limit, gas_used: 0, depth: 0 };

		let result = run(&mut tx).and_then(|(contract, outcome)| {
			let mut state = self.shared.lock();
			let operations = std::mem::take(&mut state.journal);
			let blocks = build_blocks(&mut state, &self.shared.config, &call.block, &operations)?;
			Ok(Execution {
				contract,
				data: outcome.data.map(|data| data.to_vec()),
				events: outcome.events,
				gas_used: tx.gas_used,
				operations,
				blocks,
				state_root: state.state_root(),
			})
		});

		if result.is_err() {
			*self.shared.lock() = checkpoint;
		}
		result
	}
}

#[derive(Clone, Copy)]
enum Entry {
	Instantiate,
	Execute,
}

#[derive(Default)]
struct Outcome {
	events: Vec<Event>,
	data: Option<Binary>,
}

/// One call in progress.
struct Tx<'a> {
	shared: &'a Arc<Shared>,
	block: BlockContext,
	/// Gas the call may use in total (lowered while inside a submessage
	/// with its own limit)
	gas_limit: u64,
	gas_used: u64,
	depth: usize,
}

impl Tx<'_> {
	fn create_contract(
		&mut self,
		code_id: u64,
		creator: &str,
		admin: Option<String>,
		label: &str,
	) -> Result<String, EngineError> {
		let sequencer = &self.shared.config.sequencer;
		let mut state = self.shared.lock();
		state.checksum_of(code_id)?;

		let address = next_identifier(&state, sequencer, KeyPairType::STORAGE)?;
		state.contracts.insert(
			address.clone(),
			ContractRecord {
				code_id,
				creator: creator.to_string(),
				admin,
				label: label.to_string(),
				storage: Default::default(),
			},
		);
		state
			.journal
			.push(LedgerOp::CreateIdentifier { creator: sequencer.to_string(), identifier: address.clone() });
		Ok(address)
	}

	fn call_contract(
		&mut self,
		entry: Entry,
		contract: &str,
		sender: &str,
		funds: &[Fund],
		msg: &[u8],
	) -> Result<Outcome, EngineError> {
		let limit = self.shared.config.max_call_depth;
		if self.depth >= limit {
			return Err(EngineError::DepthExceeded { limit });
		}
		self.depth += 1;
		let result = self.call_contract_at_depth(entry, contract, sender, funds, msg);
		self.depth -= 1;
		result
	}

	fn call_contract_at_depth(
		&mut self,
		entry: Entry,
		contract: &str,
		sender: &str,
		funds: &[Fund],
		msg: &[u8],
	) -> Result<Outcome, EngineError> {
		{
			let mut state = self.shared.lock();
			state.contract(contract)?;
			for fund in funds {
				parse_account_of(&fund.token, KeyPairType::TOKEN)?;
				state.transfer(sender, contract, &fund.token, &fund.amount, None)?;
			}
		}

		let env = self.shared.env(&self.block, contract);
		let info = serde_json::to_vec(&json!({
			"sender": sender,
			"funds": funds
				.iter()
				.map(|fund| json!({ "denom": fund.token, "amount": fund.amount.to_string() }))
				.collect::<Vec<_>>(),
		}))?;
		let (raw, label) = match entry {
			Entry::Instantiate => {
				(self.run(contract, |instance| call_instantiate_raw(instance, &env, &info, msg))?, "instantiate")
			}
			Entry::Execute => (self.run(contract, |instance| call_execute_raw(instance, &env, &info, msg))?, "execute"),
		};
		self.finish(contract, &raw, label)
	}

	/// Run one entry point on a fresh instance, charging its gas to the call.
	fn run(
		&mut self,
		contract: &str,
		entry_point: impl FnOnce(&mut KeetaInstance) -> VmResult<Vec<u8>>,
	) -> Result<Vec<u8>, EngineError> {
		let remaining = self.gas_limit.saturating_sub(self.gas_used);
		if remaining == 0 {
			return Err(EngineError::OutOfGas);
		}
		let mut instance = self
			.shared
			.instance(contract, self.block, self.depth, remaining)?;
		let result = entry_point(&mut instance);
		self.gas_used += gas_used(&mut instance);
		Ok(result?)
	}

	/// Interpret a contract's response: collect its events, then dispatch
	/// its messages in order.
	fn finish(&mut self, contract: &str, raw: &[u8], entry: &str) -> Result<Outcome, EngineError> {
		let result: ContractResult<Response<KeetaMsgWire>> = serde_json::from_slice(raw)?;
		let response = result
			.into_result()
			.map_err(|message| EngineError::Contract { message })?;

		let tagged = |ty: String, attributes: Vec<cosmwasm_std::Attribute>| Event {
			ty,
			attributes: std::iter::once(("_contract_address".to_string(), contract.to_string()))
				.chain(attributes.into_iter().map(|a| (a.key, a.value)))
				.collect(),
		};
		let mut events = vec![tagged(entry.to_string(), Vec::new())];
		if !response.attributes.is_empty() {
			events.push(tagged("wasm".into(), response.attributes));
		}
		for event in response.events {
			events.push(tagged(format!("wasm-{}", event.ty), event.attributes));
		}

		let mut data = response.data;
		for submessage in response.messages {
			let (sub_events, reply_data) = self.dispatch_submessage(contract, submessage)?;
			events.extend(sub_events);
			if reply_data.is_some() {
				data = reply_data;
			}
		}
		Ok(Outcome { events, data })
	}

	fn dispatch_submessage(
		&mut self,
		contract: &str,
		submessage: SubMsg<KeetaMsgWire>,
	) -> Result<(Vec<Event>, Option<Binary>), EngineError> {
		let SubMsg { id, payload, msg, gas_limit, reply_on, .. } = submessage;
		let catches_error = matches!(reply_on, ReplyOn::Error | ReplyOn::Always);
		let replies_on_success = matches!(reply_on, ReplyOn::Success | ReplyOn::Always);
		let checkpoint = catches_error.then(|| self.shared.lock().clone());

		let outer_limit = self.gas_limit;
		if let Some(limit) = gas_limit {
			self.gas_limit = outer_limit.min(self.gas_used.saturating_add(limit));
		}
		let result = self.dispatch(contract, msg);
		self.gas_limit = outer_limit;

		match result {
			Ok(outcome) if replies_on_success => {
				let reply = self.reply(contract, id, &payload, Ok(&outcome))?;
				let mut events = outcome.events;
				events.extend(reply.events);
				Ok((events, reply.data))
			}
			Ok(outcome) => Ok((outcome.events, None)),
			// Only a submessage's own gas limit can be caught; running out of
			// the call's gas always aborts the call.
			Err(EngineError::OutOfGas) if gas_limit.is_none() || self.gas_used >= outer_limit => {
				Err(EngineError::OutOfGas)
			}
			Err(error) => match checkpoint {
				Some(checkpoint) => {
					*self.shared.lock() = checkpoint;
					let reply = self.reply(contract, id, &payload, Err(error.to_string()))?;
					Ok((reply.events, reply.data))
				}
				None => Err(error),
			},
		}
	}

	fn reply(
		&mut self,
		contract: &str,
		id: u64,
		payload: &Binary,
		result: Result<&Outcome, String>,
	) -> Result<Outcome, EngineError> {
		let result = match result {
			Ok(outcome) => json!({ "ok": {
				"events": outcome.events.iter().map(event_json).collect::<Vec<_>>(),
				"data": outcome.data,
				"msg_responses": [],
			}}),
			Err(error) => json!({ "error": error }),
		};
		let reply = serde_json::to_vec(&json!({
			"id": id,
			"payload": payload,
			"gas_used": 0,
			"result": result,
		}))?;
		let env = self.shared.env(&self.block, contract);
		let raw = self.run(contract, |instance| call_reply_raw(instance, &env, &reply))?;
		self.finish(contract, &raw, "reply")
	}

	fn dispatch(&mut self, contract: &str, msg: CosmosMsg<KeetaMsgWire>) -> Result<Outcome, EngineError> {
		match msg {
			CosmosMsg::Bank(BankMsg::Send { to_address, amount }) => {
				parse_account(&to_address)?;
				let mut state = self.shared.lock();
				for coin in amount {
					parse_account_of(&coin.denom, KeyPairType::TOKEN)?;
					let value = to_biguint(&coin.amount.to_string())?;
					state.transfer(contract, &to_address, &coin.denom, &value, None)?;
				}
				Ok(Outcome::default())
			}
			CosmosMsg::Custom(KeetaMsgWire(msg)) => self.keeta(contract, msg),
			CosmosMsg::Wasm(WasmMsg::Execute { contract_addr, msg, funds }) => {
				let funds = to_funds(funds)?;
				self.call_contract(Entry::Execute, &contract_addr, contract, &funds, msg.as_slice())
			}
			CosmosMsg::Wasm(WasmMsg::Instantiate { admin, code_id, msg, funds, label }) => {
				let funds = to_funds(funds)?;
				let address = self.create_contract(code_id, contract, admin, &label)?;
				let mut outcome = self.call_contract(Entry::Instantiate, &address, contract, &funds, msg.as_slice())?;
				outcome.data = Some(instantiate_response(&address, outcome.data.as_ref()));
				Ok(outcome)
			}
			other => {
				let mut what = format!("{other:?}");
				what.truncate(200);
				Err(EngineError::Unsupported { what })
			}
		}
	}

	/// Perform a [`KeetaMsg`] as `contract`.
	fn keeta(&mut self, contract: &str, msg: KeetaMsg) -> Result<Outcome, EngineError> {
		let rules = ValidationConfig::for_network(&BigInt::from(self.shared.config.network))
			.map_err(|error| EngineError::Setup { message: error.to_string() })?;
		let sequencer = &self.shared.config.sequencer;
		let mut state = self.shared.lock();

		match msg {
			KeetaMsg::Send { to, token, amount, external } => {
				parse_account(&to)?;
				parse_account_of(&token, KeyPairType::TOKEN)?;
				if let Some(external) = &external {
					check_text("external", &rules.external, external)?;
				}
				state.transfer(contract, &to, &token, &keeta_amount(&amount)?, external)?;
			}
			KeetaMsg::SetInfo { name, description, metadata } => {
				check_text("name", &rules.name, &name)?;
				check_text("description", &rules.description, &description)?;
				check_text("metadata", &rules.metadata, &metadata)?;
				let info = AccountInfo { name, description, metadata };
				state.accounts.insert(contract.to_string(), info.clone());
				state
					.journal
					.push(LedgerOp::SetInfo { account: contract.to_string(), info });
			}
			KeetaMsg::CreateToken { subdenom, name, description } => {
				if subdenom.is_empty() || subdenom.len() > 64 {
					return Err(EngineError::InvalidField {
						field: "subdenom",
						reason: "must be 1 to 64 bytes".into(),
					});
				}
				check_text("name", &rules.name, &name)?;
				check_text("description", &rules.description, &description)?;
				let key = (contract.to_string(), subdenom);
				if state.token_registry.contains_key(&key) {
					return Err(ledger(format!("{contract} already created token {}", key.1)));
				}

				let token = next_identifier(&state, sequencer, KeyPairType::TOKEN)?;
				let info = AccountInfo { name, description, metadata: String::new() };
				state.token_registry.insert(key, token.clone());
				state
					.tokens
					.insert(token.clone(), TokenRecord { admin: contract.to_string(), supply: BigUint::ZERO });
				state.accounts.insert(token.clone(), info.clone());
				state
					.journal
					.push(LedgerOp::CreateIdentifier { creator: sequencer.to_string(), identifier: token.clone() });
				state
					.journal
					.push(LedgerOp::SetInfo { account: token, info });
			}
			KeetaMsg::Mint { subdenom, to, amount } => {
				parse_account(&to)?;
				let token = administered_token(&state, contract, &subdenom)?;
				let amount = keeta_amount(&amount)?;
				let record = state
					.tokens
					.get_mut(&token)
					.expect("registered tokens exist");
				let supply = &record.supply + &amount;
				rules
					.validate_supply(&BigInt::from(supply.clone()))
					.map_err(|error| ledger(error.to_string()))?;
				record.supply = supply;
				state.credit(&token, &token, &amount);
				state
					.journal
					.push(LedgerOp::TokenSupply { token: token.clone(), amount: amount.clone(), add: true });
				state.transfer(&token, &to, &token, &amount, None)?;
			}
			KeetaMsg::Burn { subdenom, amount } => {
				let token = administered_token(&state, contract, &subdenom)?;
				let amount = keeta_amount(&amount)?;
				state.transfer(contract, &token, &token, &amount, None)?;
				state.debit(&token, &token, &amount)?;
				let record = state
					.tokens
					.get_mut(&token)
					.expect("registered tokens exist");
				record.supply -= &amount;
				state
					.journal
					.push(LedgerOp::TokenSupply { token, amount, add: false });
			}
		}
		Ok(Outcome::default())
	}
}

/// The address of the next identifier the sequencer creates in this call.
///
/// Keeta derives an identifier from the creating account's previous block
/// hash (or nothing, for its opening block) and the operation's index in
/// the block. All of a call's creations go into one sequencer block at the
/// start of its staple (see [`build_blocks`]), so the address is known
/// while the contract runs: the sequencer's current head, and the number of
/// identifiers created so far in this call. Rolling back a submessage
/// rolls back the journal too, so the index stays consistent with the
/// block that is eventually built.
fn next_identifier(state: &ChainState, sequencer: &AccountRef, kind: KeyPairType) -> Result<String, EngineError> {
	let index = state
		.journal
		.iter()
		.filter(|op| matches!(op, LedgerOp::CreateIdentifier { .. }))
		.count();
	let previous = state.heads.get(&sequencer.to_string());
	sequencer
		.generate_identifier(kind, previous, index as u32)
		.map(|account| account.to_string())
		.map_err(|error| EngineError::Setup { message: format!("deriving identifier: {error}") })
}

fn administered_token(state: &ChainState, contract: &str, subdenom: &str) -> Result<String, EngineError> {
	state
		.token_registry
		.get(&(contract.to_string(), subdenom.to_string()))
		.cloned()
		.ok_or_else(|| ledger(format!("{contract} has not created token {subdenom}")))
}

fn check_text(field: &'static str, rule: &TextRule, value: &str) -> Result<(), EngineError> {
	rule.check(value)
		.map_err(|violation| EngineError::InvalidField { field, reason: format!("{violation:?}") })
}

fn to_biguint(decimal: &str) -> Result<BigUint, EngineError> {
	decimal
		.parse()
		.map_err(|_| EngineError::Serialization { message: format!("bad amount {decimal}") })
}

fn keeta_amount(amount: &KeetaAmount) -> Result<BigUint, EngineError> {
	let value = to_biguint(amount.as_str())?;
	if value == BigUint::ZERO {
		return Err(ledger("amount must be positive"));
	}
	Ok(value)
}

fn to_funds(coins: Vec<cosmwasm_std::Coin>) -> Result<Vec<Fund>, EngineError> {
	coins
		.into_iter()
		.map(|coin| Ok(Fund::new(coin.denom, to_biguint(&coin.amount.to_string())?)))
		.collect()
}

fn event_json(event: &Event) -> serde_json::Value {
	json!({
		"type": event.ty,
		"attributes": event
			.attributes
			.iter()
			.map(|(key, value)| json!({ "key": key, "value": value }))
			.collect::<Vec<_>>(),
	})
}

/// `MsgInstantiateContractResponse` protobuf, which is what contracts parse
/// (via `cw_utils::parse_instantiate_response_data`) to learn the address
/// of a contract they instantiated through a submessage.
fn instantiate_response(address: &str, data: Option<&Binary>) -> Binary {
	fn field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
		out.push(tag);
		let mut length = bytes.len();
		while length >= 0x80 {
			out.push((length as u8) | 0x80);
			length >>= 7;
		}
		out.push(length as u8);
		out.extend_from_slice(bytes);
	}

	let mut out = Vec::new();
	field(&mut out, 0x0a, address.as_bytes());
	if let Some(data) = data.filter(|data| !data.is_empty()) {
		field(&mut out, 0x12, data.as_slice());
	}
	Binary::from(out)
}
