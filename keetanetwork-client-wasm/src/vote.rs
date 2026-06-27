//! JS `Vote` and `VoteQuote`: representative attestations, serializable to hex.

use alloc::string::{String, ToString};

use keetanetwork_client::{Vote as CoreVote, VoteQuote as CoreVoteQuote};
use wasm_bindgen::prelude::wasm_bindgen;

/// A signed vote certificate issued by a representative.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Vote {
	inner: CoreVote,
}

#[wasm_bindgen]
impl Vote {
	/// The vote hash as a hex string.
	#[wasm_bindgen(getter)]
	pub fn hash(&self) -> String {
		self.inner.hash().to_string()
	}

	/// The vote's DER hex encoding.
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.inner.as_bytes())
	}
}

impl From<CoreVote> for Vote {
	fn from(inner: CoreVote) -> Self {
		Self { inner }
	}
}

/// A vote restricted to the quote phase: it carries the fees a publish must
/// pay. Attach one to [`TransmitOptions`](crate::options).
#[wasm_bindgen]
#[derive(Clone)]
pub struct VoteQuote {
	inner: CoreVoteQuote,
}

#[wasm_bindgen]
impl VoteQuote {
	/// The quote hash as a hex string.
	#[wasm_bindgen(getter)]
	pub fn hash(&self) -> String {
		self.inner.hash().to_string()
	}

	/// The quote's DER hex encoding.
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.inner.as_vote().as_bytes())
	}
}

impl VoteQuote {
	/// The wrapped quote, cloned for attaching to transmit options.
	pub(crate) fn inner(&self) -> CoreVoteQuote {
		self.inner.clone()
	}
}

impl From<CoreVoteQuote> for VoteQuote {
	fn from(inner: CoreVoteQuote) -> Self {
		Self { inner }
	}
}
