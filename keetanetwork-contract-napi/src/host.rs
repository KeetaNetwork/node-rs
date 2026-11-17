//! The engine's [`Host`], answered by JavaScript.
//!
//! Every read becomes one call to the JavaScript `host(request)` function
//! with a JSON [`HostRequest`]; it returns a promise of the JSON answer.
//! The engine runs on its own thread (never the JavaScript one), which
//! blocks until the promise settles, while the event loop stays free to do
//! the asynchronous work the answer needs (a database query). A rejected
//! promise becomes a [`HostError`], which aborts the call.

use keetanetwork_contract_engine::{CodeHash, ContractRecord, Host, HostError, HostResult};
use napi::bindgen_prelude::Promise;
use napi::threadsafe_function::ThreadsafeFunction;
use napi::Status;
use num_bigint::BigUint;
use serde::de::DeserializeOwned;

use crate::wire::{decode_b64, HostRequest, WireContractRecord};

/// The JavaScript `host(request: string) => Promise<string>` function.
///
/// Weak, so an idle engine does not keep the Node.js process alive; each
/// call in flight is kept alive by its own pending promise.
pub type HostFunction = ThreadsafeFunction<String, Promise<String>, String, Status, false, true>;

/// A [`Host`] that asks JavaScript.
pub struct JsHost {
	function: HostFunction,
}

impl JsHost {
	pub fn new(function: HostFunction) -> Self {
		Self { function }
	}

	/// Ask JavaScript and wait for the answer. Must not be called on the
	/// JavaScript thread: it would wait for itself.
	fn ask<T: DeserializeOwned>(&self, request: HostRequest) -> HostResult<T> {
		let text = serde_json::to_string(&request).expect("host requests serialize");
		let answer = futures::executor::block_on(async {
			let promise = self.function.call_async_catch(text).await?;
			promise.await
		})
		.map_err(|error| HostError::new(format!("host {}: {}", request.op(), error.reason)))?;
		serde_json::from_str(&answer)
			.map_err(|error| HostError::new(format!("host {} answered badly: {error}", request.op())))
	}

	fn bytes(&self, request: HostRequest) -> HostResult<Option<Vec<u8>>> {
		self.ask::<Option<String>>(request)?
			.map(|text| decode_b64(&text).map_err(|error| HostError::new(error.0)))
			.transpose()
	}
}

fn decimal(text: &str) -> HostResult<BigUint> {
	text.parse()
		.map_err(|_| HostError::new(format!("host returned a bad amount {text:?}")))
}

impl Host for JsHost {
	fn code_bytes(&self, hash: &CodeHash) -> HostResult<Option<Vec<u8>>> {
		self.bytes(HostRequest::CodeBytes { checksum: *hash })
	}

	fn contract(&self, address: &str) -> HostResult<Option<ContractRecord>> {
		let record = self.ask::<Option<WireContractRecord>>(HostRequest::Contract { address: address.to_string() })?;
		match record {
			Some(record) if record.address != address => {
				Err(HostError::new(format!("host returned {} for contract {address}", record.address)))
			}
			record => Ok(record.map(Into::into)),
		}
	}

	fn storage_get(&self, contract: &str, key: &[u8]) -> HostResult<Option<Vec<u8>>> {
		self.bytes(HostRequest::StorageGet { contract: contract.to_string(), key: key.to_vec() })
	}

	fn balance(&self, account: &str, token: &str) -> HostResult<BigUint> {
		let text: String = self.ask(HostRequest::Balance { account: account.to_string(), token: token.to_string() })?;
		decimal(&text)
	}

	fn token_supply(&self, token: &str) -> HostResult<Option<BigUint>> {
		self.ask::<Option<String>>(HostRequest::TokenSupply { token: token.to_string() })?
			.map(|text| decimal(&text))
			.transpose()
	}

	fn send_refusal(&self, from: &str, to: &str, token: &str) -> HostResult<Option<String>> {
		self.ask(HostRequest::SendRefusal { from: from.to_string(), to: to.to_string(), token: token.to_string() })
	}
}
