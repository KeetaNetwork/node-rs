//! JS `Block` and `VoteStaple`: handles to signed ledger artifacts.

use alloc::string::{String, ToString};

use keetanetwork_block::{Block as CoreBlock, Hashable};
use keetanetwork_client::VoteStaple as CoreVoteStaple;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::convert::{coded_error, JsResult};

/// A signed block produced by a [`Builder`](crate::builder) or read from a
/// node. Serializable to/from hex for storage or out-of-band transport.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Block {
	inner: CoreBlock,
}

#[wasm_bindgen]
impl Block {
	/// Decode a block from its hex wire encoding.
	#[wasm_bindgen(js_name = fromHex)]
	pub fn from_hex(hex: String) -> JsResult<Block> {
		let bytes = hex::decode(&hex).map_err(|_| coded_error("INVALID_BLOCK", "block must be hex"))?;
		let inner = CoreBlock::try_from(bytes.as_slice()).map_err(|error| coded_error("BLOCK", &error.to_string()))?;
		Ok(Self { inner })
	}

	/// The block hash as a hex string.
	#[wasm_bindgen(getter)]
	pub fn hash(&self) -> String {
		self.inner.hash().to_string()
	}

	/// The block's hex wire encoding.
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.inner.to_bytes())
	}
}

impl Block {
	/// The wrapped block, cloned for delegation to the core client.
	pub(crate) fn inner(&self) -> CoreBlock {
		self.inner.clone()
	}
}

impl From<CoreBlock> for Block {
	fn from(inner: CoreBlock) -> Self {
		Self { inner }
	}
}

/// A verified vote staple returned by sync and recover operations. Serializable
/// to hex; re-transmit it with [`KeetaClient::transmit_staple`](crate::client).
#[wasm_bindgen]
#[derive(Clone)]
pub struct VoteStaple {
	inner: CoreVoteStaple,
}

#[wasm_bindgen]
impl VoteStaple {
	/// The staple hash as a hex string.
	#[wasm_bindgen(getter)]
	pub fn hash(&self) -> String {
		self.inner.hash().to_string()
	}

	/// The staple's compressed hex wire encoding.
	#[wasm_bindgen(js_name = toHex)]
	pub fn to_hex(&self) -> String {
		hex::encode(self.inner.as_bytes())
	}
}

impl VoteStaple {
	/// The wrapped staple, borrowed for delegation to the core client.
	pub(crate) fn inner(&self) -> &CoreVoteStaple {
		&self.inner
	}
}

impl From<CoreVoteStaple> for VoteStaple {
	fn from(inner: CoreVoteStaple) -> Self {
		Self { inner }
	}
}
