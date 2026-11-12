//! # Keetanetwork Contract Engine for Node.js
//!
//! Exposes [`keetanetwork_contract_engine`] (sBPF contracts, Solana's
//! account model) to a Keeta node written in TypeScript, which runs each
//! `CONTRACT_CALL` on its ledger with it.
//!
//! - **The node owns all I/O.** The engine reads the ledger through one
//!   JavaScript callback, `host(request: string) => Promise<string>` (see
//!   [`wire::HostRequest`] for the requests and their answers). Calls run
//!   on their own thread and wait for each answer, while the event loop
//!   does the database work.
//! - **Everything crossing the boundary is JSON** (see [`wire`]). Engine
//!   failures are expected outcomes, so calls resolve to `{"ok": …}` or
//!   `{"error": {"kind", "message"}}`; promises only reject for malformed
//!   input or a crashed call.

#![allow(clippy::new_without_default)]

pub mod host;
pub mod wire;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use keetanetwork_contract_engine::{Engine, EngineError};
use napi::bindgen_prelude::{Buffer, Function, Object, Promise};
use napi::{Env, Error, Result, Status};
use napi_derive::napi;
use serde::Serialize;

use crate::host::JsHost;
use crate::wire::{Outcome, WireConfig, WireLedgerCall, WireLedgerOutcome};

fn invalid(error: impl std::fmt::Display) -> Error {
	Error::new(Status::InvalidArg, error.to_string())
}

fn parse_json<T: serde::de::DeserializeOwned>(what: &str, text: &str) -> Result<T> {
	serde_json::from_str(text).map_err(|error| invalid(format!("bad {what}: {error}")))
}

type Resolve = Box<dyn FnOnce(Env) -> Result<String> + Send>;

/// Run `work` on its own thread; the returned promise resolves to its JSON.
/// If preparing the input failed, the promise rejects instead, so callers
/// see every failure the same way.
fn spawn<'env, W: FnOnce() -> String + Send + 'static>(env: &'env Env, work: Result<W>) -> Result<Object<'env>> {
	let (deferred, promise) = env.create_deferred::<String, Resolve>()?;
	let work = match work {
		Ok(work) => work,
		Err(error) => {
			deferred.reject(error);
			return Ok(promise);
		}
	};
	std::thread::Builder::new()
		.name("keeta-contract".into())
		.spawn(move || match catch_unwind(AssertUnwindSafe(work)) {
			Ok(json) => deferred.resolve(Box::new(move |_| Ok(json))),
			Err(_) => deferred.reject(Error::from_reason("the contract engine crashed")),
		})
		.map_err(|error| Error::from_reason(format!("starting a call: {error}")))?;
	Ok(promise)
}

fn outcome<T: Serialize>(result: std::result::Result<T, EngineError>) -> String {
	Outcome::from_result(result).to_json()
}

/// What storing code returns.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredCode {
	checksum: String,
}

/// An sBPF contract engine whose state lives with the caller.
#[napi]
pub struct ContractEngine {
	engine: Arc<Engine>,
	host: Arc<JsHost>,
}

#[napi]
impl ContractEngine {
	/// `config` is JSON: `{ network, maxCallDepth?, maxCodeSize?, maxCachedCodeSize? }`. `host`
	/// answers the engine's reads (see the crate docs).
	#[napi(constructor)]
	pub fn new(config: String, host: Function<String, Promise<String>>) -> Result<Self> {
		let config = parse_json::<WireConfig>("config", &config)?.into_config();
		let engine = Engine::new(config).map_err(|error| Error::from_reason(error.to_string()))?;
		let function = host
			.build_threadsafe_function::<String>()
			.callee_handled::<false>()
			.weak::<true>()
			.build()?;
		Ok(Self { engine: Arc::new(engine), host: Arc::new(JsHost::new(function)) })
	}

	/// Check an sBPF v3 ELF file and keep it loaded. Resolves to
	/// `{ ok: { checksum } }`, the code's SHA-256 in hex.
	#[napi(ts_return_type = "Promise<string>")]
	pub fn store_code<'env>(&self, env: &'env Env, elf: Buffer) -> Result<Object<'env>> {
		let elf = elf.to_vec();
		let engine = self.engine.clone();
		spawn(
			env,
			Ok(move || {
				outcome(
					engine
						.store_code(&elf)
						.map(|checksum| StoredCode { checksum: hex::encode(checksum) }),
				)
			}),
		)
	}

	/// Run a call against the host's ledger, changing nothing. `call` is
	/// JSON `{ caller, instruction, funds?, gasLimit, timeMillis }`. Resolves
	/// to `{ ok: { data, events, logs, gasUsed, reads, writes, effects } }`,
	/// where `effects` are `SEND`s from contracts and `SET_INFO`s on them.
	#[napi(ts_return_type = "Promise<string>")]
	pub fn run_ledger_call<'env>(&self, env: &'env Env, call: String) -> Result<Object<'env>> {
		let (engine, host) = (self.engine.clone(), self.host.clone());
		let work = parse_json::<WireLedgerCall>("ledger call", &call)
			.and_then(|call| call.into_call().map_err(invalid))
			.map(|call| {
				move || {
					outcome(
						engine
							.run_ledger_call(host, &call)
							.map(WireLedgerOutcome::from),
					)
				}
			});
		spawn(env, work)
	}
}
