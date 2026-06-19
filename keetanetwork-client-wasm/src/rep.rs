//! JS `RepEndpoint`: describes a representative for a multi-rep client.

use alloc::string::String;
use core::str::FromStr;

use keetanetwork_client::RepEndpoint as Core;
use num_bigint::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::convert::{coded_error, JsResult};

/// A representative endpoint: its API URL, account, and voting weight. Pass a
/// set of these to [`KeetaClient::for_representatives`](crate::client).
#[wasm_bindgen]
pub struct RepEndpoint {
	inner: Core,
}

#[wasm_bindgen]
impl RepEndpoint {
	/// Describe a representative by its API URL, account, and voting `weight`.
	#[wasm_bindgen(constructor)]
	pub fn new(api_url: String, account: &Account, weight: String) -> JsResult<RepEndpoint> {
		let weight =
			BigInt::from_str(&weight).map_err(|_| coded_error("INVALID_WEIGHT", "weight must be a decimal integer"))?;
		Ok(Self { inner: Core::new(api_url, account.inner(), weight) })
	}
}

impl RepEndpoint {
	/// Consume the wrapper, yielding the core endpoint.
	pub(crate) fn into_inner(self) -> Core {
		self.inner
	}
}
