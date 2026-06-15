//! Backend-neutral codec for [`Block`] / [`BlockV1`] / [`BlockV2`].
//!
//! Dispatches to a `rasn`-backed implementation when the `rasn` feature is
//! enabled (the canonical schema is the rasn-compiler output for
//! `block.asn`).

use alloc::vec::Vec;

use super::types::{Block, BlockV1, BlockV2};
use crate::Asn1Error;

#[cfg(feature = "rasn")]
mod rasn_codec;

#[cfg(all(feature = "der", not(feature = "rasn")))]
mod der_codec;

/// Encode a [`BlockV1`] as canonical DER bytes.
pub fn encode_v1(value: &BlockV1) -> Result<Vec<u8>, Asn1Error> {
	#[cfg(feature = "rasn")]
	{
		rasn_codec::encode_v1(value)
	}
	#[cfg(all(feature = "der", not(feature = "rasn")))]
	{
		der_codec::encode_v1(value)
	}
}

/// Encode a [`BlockV2`] as canonical DER bytes.
pub fn encode_v2(value: &BlockV2) -> Result<Vec<u8>, Asn1Error> {
	#[cfg(feature = "rasn")]
	{
		rasn_codec::encode_v2(value)
	}
	#[cfg(all(feature = "der", not(feature = "rasn")))]
	{
		der_codec::encode_v2(value)
	}
}

/// Encode a [`Block`] (V1 or V2) as canonical DER bytes.
pub fn encode(value: &Block) -> Result<Vec<u8>, Asn1Error> {
	match value {
		Block::V1(v1) => encode_v1(v1),
		Block::V2(v2) => encode_v2(v2),
	}
}

/// Decode a [`BlockV1`] from canonical DER bytes.
pub fn decode_v1(bytes: &[u8]) -> Result<BlockV1, Asn1Error> {
	#[cfg(feature = "rasn")]
	{
		rasn_codec::decode_v1(bytes)
	}
	#[cfg(all(feature = "der", not(feature = "rasn")))]
	{
		der_codec::decode_v1(bytes)
	}
}

/// Decode a [`BlockV2`] from canonical DER bytes.
pub fn decode_v2(bytes: &[u8]) -> Result<BlockV2, Asn1Error> {
	#[cfg(feature = "rasn")]
	{
		rasn_codec::decode_v2(bytes)
	}
	#[cfg(all(feature = "der", not(feature = "rasn")))]
	{
		der_codec::decode_v2(bytes)
	}
}

/// Decode a [`Block`] from canonical DER bytes, dispatching on the outer tag
/// (`0x30` ⇒ V1, `0xA1` ⇒ V2).
pub fn decode(bytes: &[u8]) -> Result<Block, Asn1Error> {
	match bytes.first() {
		Some(0x30) => decode_v1(bytes).map(Block::V1),
		Some(0xA1) => decode_v2(bytes).map(Block::V2),
		_ => Err(Asn1Error::InvalidBlockVersion),
	}
}
