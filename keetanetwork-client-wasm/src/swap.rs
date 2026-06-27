//! JS `SwapExpectation`: optional assertions a taker applies when accepting.

use alloc::string::String;

use keetanetwork_client::SwapExpectation as Core;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::convert::{parse_amount, JsResult};

/// Optional token/amount assertions for the legs of a swap being accepted.
/// Assert the leg the taker receives, and assert or raise the leg it sends.
#[wasm_bindgen]
#[derive(Default)]
pub struct SwapExpectation {
	inner: Core,
}

#[wasm_bindgen]
impl SwapExpectation {
	/// No assertions.
	#[wasm_bindgen(constructor)]
	pub fn new() -> SwapExpectation {
		Self::default()
	}

	/// Assert the token the taker receives (what the maker sends).
	#[wasm_bindgen(js_name = setReceiveToken)]
	pub fn set_receive_token(&mut self, token: &Account) {
		self.inner
			.receive
			.get_or_insert_with(Default::default)
			.token = Some(token.inner());
	}

	/// Assert the amount the taker receives.
	#[wasm_bindgen(js_name = setReceiveAmount)]
	pub fn set_receive_amount(&mut self, amount: String) -> JsResult<()> {
		self.inner
			.receive
			.get_or_insert_with(Default::default)
			.amount = Some(parse_amount(&amount)?);
		Ok(())
	}

	/// Assert the token the taker sends to the maker.
	#[wasm_bindgen(js_name = setSendToken)]
	pub fn set_send_token(&mut self, token: &Account) {
		self.inner.send.get_or_insert_with(Default::default).token = Some(token.inner());
	}

	/// Assert or raise the amount the taker sends to the maker.
	#[wasm_bindgen(js_name = setSendAmount)]
	pub fn set_send_amount(&mut self, amount: String) -> JsResult<()> {
		self.inner.send.get_or_insert_with(Default::default).amount = Some(parse_amount(&amount)?);
		Ok(())
	}
}

impl SwapExpectation {
	pub(crate) fn to_core(&self) -> Core {
		self.inner.clone()
	}
}
