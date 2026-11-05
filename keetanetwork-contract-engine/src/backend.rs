//! The VM backend: storage and querier implementations over [`ChainState`].
//!
//! Locking rule: the state mutex is only ever held for the duration of a
//! single backend call and never while Wasm runs, so nested instances
//! (smart queries, contract-to-contract calls) cannot deadlock.

use std::ops::Bound;
use std::sync::{Arc, Mutex, MutexGuard};

use cosmwasm_std::{Binary, ContractResult, Order, QueryRequest, SystemError, SystemResult};
use cosmwasm_vm::{
	call_query_raw, Backend, BackendError, BackendResult, Cache, GasInfo, Instance, InstanceOptions, Querier, Storage,
};
use keetanetwork_contract_std::{AccountInfoResponse, KeetaQuery, TokenAddressResponse, TokenInfoResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::address::{parse_account, KeetaApi};
use crate::engine::EngineConfig;
use crate::error::EngineError;
use crate::state::ChainState;

/// Placeholder gas schedule, in CosmWasm gas. Only the shape matters for
/// the spike: storage and queries cost something, proportional to size.
pub(crate) mod gas {
	pub const STORAGE_BASE: u64 = 1_000_000;
	pub const STORAGE_PER_BYTE: u64 = 10_000;
	pub const QUERY_BASE: u64 = 2_000_000;
}

/// When a call happens, as seen by contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockContext {
	/// Sequencer height: one per committed call
	pub height: u64,
	/// Milliseconds since the Unix epoch (Keeta block time resolution)
	pub time_millis: i64,
}

impl BlockContext {
	pub(crate) fn time_nanos(&self) -> u64 {
		(self.time_millis.max(0) as u64).saturating_mul(1_000_000)
	}
}

pub(crate) type KeetaCache = Cache<KeetaApi, ContractStorage, KeetaQuerier>;
pub(crate) type KeetaInstance = Instance<KeetaApi, ContractStorage, KeetaQuerier>;

/// State shared by the engine and every live instance.
pub(crate) struct Shared {
	pub(crate) cache: KeetaCache,
	pub(crate) state: Mutex<ChainState>,
	pub(crate) config: EngineConfig,
}

impl Shared {
	pub(crate) fn lock(&self) -> MutexGuard<'_, ChainState> {
		// A poisoned lock means a panic mid-update; the state cannot be trusted.
		self.state.lock().expect("chain state lock poisoned")
	}

	/// The JSON `Env` a contract sees.
	pub(crate) fn env(&self, block: &BlockContext, contract: &str) -> Vec<u8> {
		serde_json::to_vec(&json!({
			"block": {
				"height": block.height,
				"time": block.time_nanos().to_string(),
				"chain_id": self.config.chain_id,
			},
			"transaction": { "index": 0 },
			"contract": { "address": contract },
		}))
		.expect("env is serializable")
	}

	/// An instance of `contract`'s code wired to this engine's state.
	pub(crate) fn instance(
		self: &Arc<Self>,
		contract: &str,
		block: BlockContext,
		depth: usize,
		gas_limit: u64,
	) -> Result<KeetaInstance, EngineError> {
		let checksum = {
			let state = self.lock();
			let code_id = state.contract(contract)?.code_id;
			state.checksum_of(code_id)?
		};
		let backend = Backend {
			api: KeetaApi,
			storage: ContractStorage::new(self.clone(), contract),
			querier: KeetaQuerier { shared: self.clone(), block, depth },
		};
		Ok(self
			.cache
			.get_instance(&checksum, backend, InstanceOptions { gas_limit })?)
	}
}

/// Gas used so far by an instance.
pub(crate) fn gas_used(instance: &mut KeetaInstance) -> u64 {
	let report = instance.create_gas_report();
	report.limit.saturating_sub(report.remaining)
}

type Record = (Vec<u8>, Vec<u8>);

/// A materialized range scan and how far it has been read.
struct ScanIterator {
	records: Vec<Record>,
	position: usize,
}

/// One contract's key-value store.
pub struct ContractStorage {
	shared: Arc<Shared>,
	contract: String,
	/// Iterators are materialized when created, so they see a consistent
	/// snapshot and ids are assigned deterministically (1, 2, …).
	iterators: Vec<ScanIterator>,
}

impl ContractStorage {
	pub(crate) fn new(shared: Arc<Shared>, contract: &str) -> Self {
		Self { shared, contract: contract.to_string(), iterators: Vec::new() }
	}
}

fn storage_gas(bytes: usize) -> GasInfo {
	GasInfo::with_externally_used(gas::STORAGE_BASE + gas::STORAGE_PER_BYTE * bytes as u64)
}

fn no_contract(contract: &str) -> BackendError {
	BackendError::unknown(format!("no contract at {contract}"))
}

impl Storage for ContractStorage {
	fn get(&self, key: &[u8]) -> BackendResult<Option<Vec<u8>>> {
		let state = self.shared.lock();
		let Some(contract) = state.contracts.get(&self.contract) else {
			return (Err(no_contract(&self.contract)), storage_gas(key.len()));
		};
		let value = contract.storage.get(key).cloned();
		let size = key.len() + value.as_ref().map_or(0, Vec::len);
		(Ok(value), storage_gas(size))
	}

	fn scan(&mut self, start: Option<&[u8]>, end: Option<&[u8]>, order: Order) -> BackendResult<u32> {
		let state = self.shared.lock();
		let Some(contract) = state.contracts.get(&self.contract) else {
			return (Err(no_contract(&self.contract)), storage_gas(0));
		};
		let empty = matches!((start, end), (Some(start), Some(end)) if start >= end);
		let mut records: Vec<_> = if empty {
			Vec::new()
		} else {
			let lower = start.map_or(Bound::Unbounded, Bound::Included);
			let upper = end.map_or(Bound::Unbounded, Bound::Excluded);
			contract
				.storage
				.range::<[u8], _>((lower, upper))
				.map(|(key, value)| (key.clone(), value.clone()))
				.collect()
		};
		if order == Order::Descending {
			records.reverse();
		}
		drop(state);
		self.iterators.push(ScanIterator { records, position: 0 });
		(Ok(self.iterators.len() as u32), storage_gas(0))
	}

	fn next(&mut self, iterator_id: u32) -> BackendResult<Option<Record>> {
		let Some(iterator) = (iterator_id as usize)
			.checked_sub(1)
			.and_then(|index| self.iterators.get_mut(index))
		else {
			return (Err(BackendError::iterator_does_not_exist(iterator_id)), storage_gas(0));
		};
		let record = iterator.records.get(iterator.position).cloned();
		if record.is_some() {
			iterator.position += 1;
		}
		let size = record
			.as_ref()
			.map_or(0, |(key, value)| key.len() + value.len());
		(Ok(record), storage_gas(size))
	}

	fn set(&mut self, key: &[u8], value: &[u8]) -> BackendResult<()> {
		let mut state = self.shared.lock();
		let Some(contract) = state.contracts.get_mut(&self.contract) else {
			return (Err(no_contract(&self.contract)), storage_gas(key.len()));
		};
		contract.storage.insert(key.to_vec(), value.to_vec());
		(Ok(()), storage_gas(key.len() + value.len()))
	}

	fn remove(&mut self, key: &[u8]) -> BackendResult<()> {
		let mut state = self.shared.lock();
		let Some(contract) = state.contracts.get_mut(&self.contract) else {
			return (Err(no_contract(&self.contract)), storage_gas(key.len()));
		};
		contract.storage.remove(key);
		(Ok(()), storage_gas(key.len()))
	}
}

/// Lets the engine parse `QueryRequest<KeetaQuery>` with cosmwasm-std 3
/// types while `KeetaQuery` itself stays free of cosmwasm-std.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(transparent)]
pub(crate) struct KeetaQueryWire(pub KeetaQuery);

impl cosmwasm_std::CustomQuery for KeetaQueryWire {}

type QueryOutcome = SystemResult<ContractResult<Binary>>;

/// Answers queries from contracts.
pub struct KeetaQuerier {
	shared: Arc<Shared>,
	block: BlockContext,
	depth: usize,
}

fn ok_json(value: serde_json::Value) -> QueryOutcome {
	SystemResult::Ok(ContractResult::Ok(Binary::from(
		serde_json::to_vec(&value).expect("query response is serializable"),
	)))
}

fn respond<T: Serialize>(value: &T) -> QueryOutcome {
	ok_json(serde_json::to_value(value).expect("query response is serializable"))
}

fn query_err(error: impl ToString) -> QueryOutcome {
	SystemResult::Ok(ContractResult::Err(error.to_string()))
}

impl Querier for KeetaQuerier {
	fn query_raw(&self, request: &[u8], gas_limit: u64) -> BackendResult<QueryOutcome> {
		let base = GasInfo::with_externally_used(gas::QUERY_BASE);
		let request: QueryRequest<KeetaQueryWire> = match serde_json::from_slice(request) {
			Ok(request) => request,
			Err(error) => {
				let outcome = SystemResult::Err(SystemError::InvalidRequest {
					error: error.to_string(),
					request: Binary::from(request),
				});
				return (Ok(outcome), base);
			}
		};

		match request {
			QueryRequest::Wasm(cosmwasm_std::WasmQuery::Smart { contract_addr, msg }) => {
				self.smart_query(&contract_addr, msg.as_slice(), gas_limit)
			}
			other => (Ok(self.answer(other)), base),
		}
	}
}

impl KeetaQuerier {
	/// Everything except smart queries: plain reads of state.
	fn answer(&self, request: QueryRequest<KeetaQueryWire>) -> QueryOutcome {
		let state = self.shared.lock();
		match request {
			QueryRequest::Bank(cosmwasm_std::BankQuery::Balance { address, denom }) => {
				let amount = state.balance(&address, &denom);
				ok_json(json!({ "amount": { "denom": denom, "amount": amount.to_string() } }))
			}
			QueryRequest::Bank(cosmwasm_std::BankQuery::Supply { denom }) => {
				let supply = state
					.tokens
					.get(&denom)
					.map(|token| token.supply.clone())
					.unwrap_or_default();
				ok_json(json!({ "amount": { "denom": denom, "amount": supply.to_string() } }))
			}
			QueryRequest::Wasm(cosmwasm_std::WasmQuery::Raw { contract_addr, key }) => {
				match state.contracts.get(&contract_addr) {
					Some(contract) => SystemResult::Ok(ContractResult::Ok(Binary::from(
						contract
							.storage
							.get(key.as_slice())
							.cloned()
							.unwrap_or_default(),
					))),
					None => SystemResult::Err(SystemError::NoSuchContract { addr: contract_addr }),
				}
			}
			QueryRequest::Wasm(cosmwasm_std::WasmQuery::ContractInfo { contract_addr }) => {
				match state.contracts.get(&contract_addr) {
					Some(contract) => ok_json(json!({
						"code_id": contract.code_id,
						"creator": contract.creator,
						"admin": contract.admin,
						"pinned": false,
						"ibc_port": null,
					})),
					None => SystemResult::Err(SystemError::NoSuchContract { addr: contract_addr }),
				}
			}
			QueryRequest::Wasm(cosmwasm_std::WasmQuery::CodeInfo { code_id }) => match state.checksum_of(code_id) {
				Ok(checksum) => ok_json(json!({
					"code_id": code_id,
					"creator": self.shared.config.sequencer.to_string(),
					"checksum": checksum.to_hex(),
				})),
				Err(_) => SystemResult::Err(SystemError::NoSuchCode { code_id }),
			},
			QueryRequest::Custom(KeetaQueryWire(query)) => answer_keeta(&state, query),
			other => SystemResult::Err(SystemError::UnsupportedRequest { kind: format!("{other:?}") }),
		}
	}

	/// Run another contract's `query` entry point, read-only.
	fn smart_query(&self, contract: &str, msg: &[u8], gas_limit: u64) -> BackendResult<QueryOutcome> {
		let base = GasInfo::with_externally_used(gas::QUERY_BASE);
		if self.depth + 1 > self.shared.config.max_call_depth {
			let error = EngineError::DepthExceeded { limit: self.shared.config.max_call_depth };
			return (Ok(query_err(error)), base);
		}
		if !self.shared.lock().contracts.contains_key(contract) {
			let outcome = SystemResult::Err(SystemError::NoSuchContract { addr: contract.to_string() });
			return (Ok(outcome), base);
		}

		let mut instance = match self
			.shared
			.instance(contract, self.block, self.depth + 1, gas_limit)
		{
			Ok(instance) => instance,
			Err(error) => return (Ok(query_err(error)), base),
		};
		let env = self.shared.env(&self.block, contract);
		let result = call_query_raw(&mut instance, &env, msg);
		let used = gas_used(&mut instance);
		let gas = GasInfo::with_externally_used(gas::QUERY_BASE + used);

		match result {
			Ok(bytes) => match serde_json::from_slice::<ContractResult<Binary>>(&bytes) {
				Ok(result) => (Ok(SystemResult::Ok(result)), gas),
				Err(error) => (Ok(query_err(format!("bad query response: {error}"))), gas),
			},
			Err(cosmwasm_vm::VmError::GasDepletion { .. }) => (Err(BackendError::out_of_gas()), gas),
			Err(error) => (Ok(query_err(error)), gas),
		}
	}
}

fn answer_keeta(state: &ChainState, query: KeetaQuery) -> QueryOutcome {
	match query {
		KeetaQuery::AccountInfo { account } => {
			if let Err(error) = parse_account(&account) {
				return query_err(error);
			}
			let info = state.accounts.get(&account).cloned().unwrap_or_default();
			respond(&AccountInfoResponse { name: info.name, description: info.description, metadata: info.metadata })
		}
		KeetaQuery::TokenAddress { creator, subdenom } => match state.token_registry.get(&(creator, subdenom)) {
			Some(token) => respond(&TokenAddressResponse { token: token.clone() }),
			None => query_err("no such token"),
		},
		KeetaQuery::TokenInfo { token } => match state.tokens.get(&token) {
			Some(record) => respond(&TokenInfoResponse {
				token,
				admin: Some(record.admin.clone()),
				supply: keetanetwork_contract_std::KeetaAmount::parse(record.supply.to_string())
					.expect("decimal digits"),
			}),
			None => query_err("no such token"),
		},
	}
}
