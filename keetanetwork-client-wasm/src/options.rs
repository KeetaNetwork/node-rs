//! JS `TransmitOptions`: publish-time controls passed to publish/transmit.

use keetanetwork_client::TransmitOptions as Core;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::vote::VoteQuote;

/// Controls for a publish or transmit round. Construct with `new()` for
/// defaults, then layer on a fee signer, fee-token preference, or quotes.
#[wasm_bindgen]
#[derive(Default)]
pub struct TransmitOptions {
	inner: Core,
}

#[wasm_bindgen]
impl TransmitOptions {
	/// Default options: no fee signer, no quotes, base-token fee preference.
	#[wasm_bindgen(constructor)]
	pub fn new() -> TransmitOptions {
		Self::default()
	}

	/// Account that originates and signs a fee block when the votes require
	/// one. Without it, a required fee fails with `FEE_REQUIRED`.
	#[wasm_bindgen(js_name = setFeeSigner)]
	pub fn set_fee_signer(&mut self, signer: &Account) {
		self.inner.fee_signer = Some(signer.inner());
	}

	/// Append a token to the fee-token preference order, highest priority
	/// first, used when a fee is payable in several tokens.
	#[wasm_bindgen(js_name = addFeeTokenPriority)]
	pub fn add_fee_token_priority(&mut self, token: &Account) {
		self.inner.fee_token_priority.push(token.inner());
	}

	/// Attach a pre-fetched vote quote; it is routed to the representative
	/// that issued it.
	#[wasm_bindgen(js_name = addQuote)]
	pub fn add_quote(&mut self, quote: &VoteQuote) {
		self.inner.quotes.push(quote.inner());
	}
}

impl TransmitOptions {
	/// The wrapped options, cloned for a single core call.
	pub(crate) fn to_core(&self) -> Core {
		self.inner.clone()
	}
}
