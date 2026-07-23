//! JS `TransmitOptions`: publish-time controls passed to publish/transmit.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem;

use js_sys::{Array, Function, Promise};
use keetanetwork_block::{AccountRef, Block as CoreBlock};
use keetanetwork_client::{
	ClientError, KeetaClient as CoreClient, TransmitOptions as Core, VoteStaple as CoreVoteStaple,
};
use wasm_bindgen::convert::TryFromJsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use crate::account::Account;
use crate::block::{Block, VoteStaple};
use crate::client::KeetaClient;
use crate::vote::VoteQuote;

/// Controls for a publish or transmit round. Construct with `new()` for
/// defaults, then layer on a fee payer, fee-token preference, or quotes.
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

	/// Account that pays and signs a fee block when the votes require one.
	/// Without it, a required fee fails with `FEE_REQUIRED`.
	#[wasm_bindgen(js_name = setFeeSigner)]
	pub fn set_fee_signer(&mut self, signer: &Account) {
		self.inner = mem::take(&mut self.inner).with_fee_signer(&signer.inner());
	}

	/// Pay any required fee from `account`, signed by `signer`. For a payer
	/// that signs for itself, prefer `setFeeSigner`.
	#[wasm_bindgen(js_name = setFeeBlockFrom)]
	pub fn set_fee_block_from(&mut self, account: &Account, signer: &Account) {
		self.inner = mem::take(&mut self.inner).with_fee_block_from(&account.inner(), &signer.inner());
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

	/// Custom fee-block factory `(client, staple, priority) => Block`, invoked
	/// when the votes require a fee; the block it resolves to (a promise is
	/// awaited) joins the staple. `KeetaClient.buildFeeBlock` is the common
	/// implementation. For a payer known up front, prefer `setFeeSigner` or
	/// `setFeeBlockFrom`.
	#[wasm_bindgen(js_name = setGenerateFeeBlock)]
	pub fn set_generate_fee_block(&mut self, factory: &Function) {
		let factory = factory.clone();
		self.inner.generate_fee_block = Some(Arc::new(move |client, staple, priority| {
			let factory = factory.clone();
			Box::pin(async move { generate_via_js(&factory, client, staple, priority).await })
		}));
	}
}

/// Invoke the JS fee-block factory and coerce its settled result to a block.
async fn generate_via_js(
	factory: &Function,
	client: CoreClient,
	staple: CoreVoteStaple,
	priority: Vec<AccountRef>,
) -> Result<CoreBlock, ClientError> {
	let client = JsValue::from(KeetaClient::from(client));
	let staple = JsValue::from(VoteStaple::from(staple));
	let tokens = Array::new();
	for token in priority {
		tokens.push(&JsValue::from(Account::from(token)));
	}

	let returned = factory
		.call3(&JsValue::NULL, &client, &staple, &tokens)
		.map_err(factory_failure)?;
	let settled = JsFuture::from(Promise::resolve(&returned))
		.await
		.map_err(factory_failure)?;
	let block = Block::try_from_js_value(settled)
		.map_err(|_| factory_failure(JsValue::from_str("fee-block factory must resolve to a Block")))?;

	Ok(block.inner())
}

/// The thrown JS value, stringified: a `JsValue` cannot itself cross into the
/// core error chain as a `core::error::Error` source.
#[derive(Debug)]
struct FactoryFailure(String);

impl fmt::Display for FactoryFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(&self.0)
	}
}

impl core::error::Error for FactoryFailure {}

/// Project a value thrown by the JS factory onto the client error taxonomy.
fn factory_failure(thrown: JsValue) -> ClientError {
	let message = thrown
		.dyn_ref::<js_sys::Error>()
		.map(|error| String::from(error.message()))
		.or_else(|| thrown.as_string())
		.unwrap_or_else(|| String::from("fee-block factory threw a non-Error value"));

	ClientError::FeeBlockFactory { source: Box::new(FactoryFailure(message)) }
}

impl TransmitOptions {
	/// The wrapped options, cloned for a single core call.
	pub(crate) fn to_core(&self) -> Core {
		self.inner.clone()
	}
}
