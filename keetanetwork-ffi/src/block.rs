//! `keetanetwork-block` surface.

use std::sync::Arc;

use keetanetwork_block::{Block as CoreBlock, BlockPurpose, BlockVersion, Hashable};

use crate::error::FfiError;

/// Opaque handle to a decoded, signature-verified block.
#[derive(uniffi::Object)]
pub struct Block(CoreBlock);

impl Block {
	/// Wrap an already-decoded core block in a shared FFI handle.
	pub(crate) fn wrap(block: CoreBlock) -> Arc<Self> {
		Arc::new(Self(block))
	}
}

#[uniffi::export]
impl Block {
	/// Decode and verify signed block DER bytes.
	#[uniffi::constructor]
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Block>, FfiError> {
		Ok(Block::wrap(CoreBlock::try_from(bytes.as_slice())?))
	}

	/// Signed DER bytes as transmitted on the network.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.0.to_bytes().to_vec()
	}

	/// Block hash as uppercase hex.
	pub fn hash_hex(&self) -> String {
		hex::encode_upper(self.0.hash().as_bytes())
	}

	/// The block version.
	pub fn version(&self) -> BlockVersion {
		self.0.data().version()
	}

	/// The declared block purpose.
	pub fn purpose(&self) -> BlockPurpose {
		self.0.data().purpose()
	}

	/// The network identifier as a decimal string.
	pub fn network(&self) -> String {
		self.0.data().network().to_string()
	}

	/// The subnet identifier as a decimal string, when present.
	pub fn subnet(&self) -> Option<String> {
		self.0.data().subnet().map(ToString::to_string)
	}

	/// The idempotent key bytes, when present.
	pub fn idempotent(&self) -> Option<Vec<u8>> {
		self.0.data().idempotent().map(<[u8]>::to_vec)
	}

	/// The block timestamp as Unix milliseconds.
	pub fn date_ms(&self) -> i64 {
		self.0.data().date().unix_millis()
	}

	/// The account the block operates on, as its public-key string.
	pub fn account(&self) -> String {
		self.0.data().account().to_string()
	}

	/// The previous block hash as uppercase hex.
	pub fn previous_hex(&self) -> String {
		hex::encode_upper(self.0.data().previous().as_bytes())
	}

	/// Whether this is the opening block of its account.
	pub fn is_opening(&self) -> bool {
		self.0.data().is_opening()
	}

	/// The number of operations carried by the block.
	pub fn operation_count(&self) -> u32 {
		self.0.data().operations().len() as u32
	}

	/// The block signatures as uppercase hex strings.
	pub fn signatures(&self) -> Vec<String> {
		self.0
			.signatures()
			.iter()
			.map(|signature| hex::encode_upper(signature.as_bytes()))
			.collect()
	}
}
