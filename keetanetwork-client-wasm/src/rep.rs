//! JS `RepEndpoint`: describes a representative for a multi-rep client.

use alloc::string::String;

use keetanetwork_client::RepEndpoint as Core;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;

/// A representative endpoint: its API URL, account, and voting weight. Pass a
/// set of these to [`KeetaClient::for_representatives`](crate::client).
#[wasm_bindgen]
pub struct RepEndpoint {
	inner: Core,
}

#[wasm_bindgen]
impl RepEndpoint {
	/// Describe a representative by its API URL, account, and voting weight.
	#[wasm_bindgen(constructor)]
	pub fn new(api_url: String, account: &Account, weight: u32) -> RepEndpoint {
		Self { inner: Core::new(api_url, account.inner(), weight) }
	}
}

impl RepEndpoint {
	/// Consume the wrapper, yielding the core endpoint.
	pub(crate) fn into_inner(self) -> Core {
		self.inner
	}
}
