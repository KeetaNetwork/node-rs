//! Vote certificate extension TLVs (`hashData` and `fees`).
//!
//! Each vote certificate's `extensions` field contains zero or more
//! X.509 `Extension` TLVs. The vote crate emits exactly two:
//!
//! * **`hashData`** - the SHA3-256 digest list of the blocks the vote
//!   covers, wrapped as `[0] EXPLICIT { SHA3-256 OID, SEQUENCE OF
//!   OCTET STRING }`. Always present.
//! * **`fees`** - the optional fee schedule (see [`crate::Fees`]).

use der::asn1::OctetStringRef;
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber};
use keetanetwork_block::BlockHash;

use crate::error::VoteError;
use crate::fee::Fees;
use crate::oids::{FEES, HASH_DATA, SHA3_256};
use crate::wire::{
	encode_octet, peek_tag, read_explicit_context, read_octet, read_sequence, unexpected_tag, wrap_explicit_context,
	wrap_sequence,
};

const HASH_DATA_OUTER_TAG: TagNumber = TagNumber::N0;

/// A parsed extension element from the vote's TBS certificate.
#[derive(Debug, Clone)]
pub(crate) struct Extension<'a> {
	pub(crate) oid: der::oid::ObjectIdentifier,
	pub(crate) critical: bool,
	pub(crate) value: &'a [u8],
}

/// Encode the vote's `hashData` extension body (the contents of its OCTET
/// STRING wrapper).
pub(crate) fn encode_hash_data(blocks: &[BlockHash]) -> Result<Vec<u8>, VoteError> {
	let mut hashes_content = Vec::new();
	for hash in blocks {
		encode_octet(&mut hashes_content, hash.as_bytes())?;
	}

	let hashes_sequence = wrap_sequence(&hashes_content)?;
	let mut inner = Vec::new();
	SHA3_256.encode_to_vec(&mut inner)?;
	inner.extend_from_slice(&hashes_sequence);

	let inner_sequence = wrap_sequence(&inner)?;
	wrap_explicit_context(HASH_DATA_OUTER_TAG, &inner_sequence)
}

/// Decode the contents of a vote's `hashData` extension.
pub(crate) fn decode_hash_data(bytes: &[u8]) -> Result<Vec<BlockHash>, VoteError> {
	let mut outer_reader = SliceReader::new(bytes).map_err(|_| VoteError::MalformedHashesFromVoteInvalidInput)?;
	let outer_inner = read_explicit_context(&mut outer_reader, HASH_DATA_OUTER_TAG).map_err(|err| match err {
		VoteError::Der { .. } => VoteError::MalformedHashesFromVoteInvalidType,
		other => other,
	})?;
	if !outer_reader.is_finished() {
		return Err(VoteError::MalformedHashesFromVoteInvalidInput);
	}

	let mut sequence_reader =
		SliceReader::new(outer_inner).map_err(|_| VoteError::MalformedHashesFromVoteDataHashDataMustBeSequence)?;
	let sequence_bytes = read_sequence(&mut sequence_reader)
		.map_err(|_| VoteError::MalformedHashesFromVoteDataHashDataMustBeSequence)?;
	if !sequence_reader.is_finished() {
		return Err(VoteError::MalformedHashesFromVoteDataNotTwoItems);
	}

	let mut inner_reader =
		SliceReader::new(sequence_bytes).map_err(|_| VoteError::MalformedHashesFromVoteDataHashDataMustBeSequence)?;

	let oid = der::asn1::ObjectIdentifier::decode(&mut inner_reader)
		.map_err(|_| VoteError::MalformedHashesFromVoteDataNeedsOid)?;
	if oid != SHA3_256 {
		return Err(VoteError::MalformedHashesFromVoteDataUnsupportedHashFunc);
	}

	let hashes_bytes =
		read_sequence(&mut inner_reader).map_err(|_| VoteError::MalformedHashesFromVoteDataSecondMustBeSequence)?;
	if !inner_reader.is_finished() {
		return Err(VoteError::MalformedHashesFromVoteDataNotTwoItems);
	}

	let mut hashes_reader =
		SliceReader::new(hashes_bytes).map_err(|_| VoteError::MalformedHashesFromVoteDataSecondMustBeSequence)?;
	let mut output = Vec::new();
	while !hashes_reader.is_finished() {
		let raw =
			read_octet(&mut hashes_reader).map_err(|_| VoteError::MalformedHashesFromVoteDataUnsupportedHashType)?;
		let hash = BlockHash::try_from(raw).map_err(|_| VoteError::MalformedHashesFromVoteDataUnsupportedHashType)?;
		output.push(hash);
	}

	Ok(output)
}

/// Decode a single extension element (X.509 `Extension ::= SEQUENCE`).
///
/// `sequence_tlv` must be the full DER bytes of the extension `SEQUENCE`,
/// including the outer `SEQUENCE` tag and length.
pub(crate) fn decode_extension(sequence_tlv: &[u8]) -> Result<Extension<'_>, VoteError> {
	let mut outer = SliceReader::new(sequence_tlv).map_err(|_| VoteError::MalformedVoteExtensionsValue)?;
	let inner_bytes = read_sequence(&mut outer).map_err(|_| VoteError::MalformedVoteExtensionsValue)?;
	if !outer.is_finished() {
		return Err(VoteError::MalformedVoteExtensionsValue);
	}

	let mut reader = SliceReader::new(inner_bytes).map_err(|_| VoteError::MalformedVoteExtensionsValue)?;
	let oid =
		der::asn1::ObjectIdentifier::decode(&mut reader).map_err(|_| VoteError::MalformedVoteExtensionsValueOid)?;

	let critical = match peek_tag(&reader)? {
		Tag::Boolean => bool::decode(&mut reader).map_err(|_| VoteError::MalformedVoteExtensionsValueCritical)?,
		Tag::OctetString => true,
		actual => return Err(unexpected_tag(actual)),
	};

	let value = OctetStringRef::decode(&mut reader)
		.map_err(|_| VoteError::MalformedVoteExtensionsData)?
		.as_bytes();
	if !reader.is_finished() {
		return Err(VoteError::MalformedVoteExtensionsValue);
	}

	Ok(Extension { oid, critical, value })
}

/// Encode an extension with `critical = true`.
pub(crate) fn encode_extension_critical(oid: der::oid::ObjectIdentifier, value: &[u8]) -> Result<Vec<u8>, VoteError> {
	let mut content = Vec::new();
	oid.encode_to_vec(&mut content)?;
	true.encode_to_vec(&mut content)?;
	encode_octet(&mut content, value)?;
	wrap_sequence(&content)
}

/// Encode the full extension TLV for `hashData`.
pub(crate) fn encode_hash_data_extension(blocks: &[BlockHash]) -> Result<Vec<u8>, VoteError> {
	let body = encode_hash_data(blocks)?;
	encode_extension_critical(HASH_DATA, &body)
}

/// Encode the full extension TLV for `fees`.
pub(crate) fn encode_fees_extension(fees: &Fees) -> Result<Vec<u8>, VoteError> {
	let body = fees.encode_extension_body()?;
	encode_extension_critical(FEES, &body)
}

#[cfg(test)]
mod tests {
	use super::*;

	use keetanetwork_block::Amount;

	use crate::error::VoteError;
	use crate::fee::{Fee, Fees};

	#[test]
	fn test_hash_data_round_trip_one_block() -> Result<(), VoteError> {
		let blocks = vec![BlockHash::from([7u8; 32])];
		let bytes = encode_hash_data(&blocks)?;
		assert_eq!(decode_hash_data(&bytes)?, blocks);
		Ok(())
	}

	#[test]
	fn test_hash_data_round_trip_many_blocks() -> Result<(), VoteError> {
		let blocks: Vec<BlockHash> = (0..5).map(|i| BlockHash::from([i as u8; 32])).collect();
		let bytes = encode_hash_data(&blocks)?;
		assert_eq!(decode_hash_data(&bytes)?, blocks);
		Ok(())
	}

	#[test]
	fn test_hash_data_extension_round_trip() -> Result<(), VoteError> {
		let blocks = vec![BlockHash::from([2u8; 32])];
		let bytes = encode_hash_data_extension(&blocks)?;
		let parsed = decode_extension(&bytes)?;
		assert_eq!(parsed.oid, HASH_DATA);
		assert!(parsed.critical);
		assert_eq!(decode_hash_data(parsed.value)?, blocks);
		Ok(())
	}

	#[test]
	fn test_fees_extension_round_trip() -> Result<(), VoteError> {
		let fees = Fees::Single { quote: false, fee: Fee { amount: Amount::from(7u64), pay_to: None, token: None } };
		let bytes = encode_fees_extension(&fees)?;
		let parsed = decode_extension(&bytes)?;
		assert_eq!(parsed.oid, FEES);
		assert!(parsed.critical);
		Fees::decode_extension_body(parsed.value)?;
		Ok(())
	}

	#[test]
	fn test_extension_default_critical_when_omitted() -> Result<(), VoteError> {
		let value = b"value";
		let mut content = Vec::new();
		HASH_DATA.encode_to_vec(&mut content)?;
		encode_octet(&mut content, value)?;
		let bytes = wrap_sequence(&content)?;
		let parsed = decode_extension(&bytes)?;
		assert!(parsed.critical);
		assert_eq!(parsed.value, value);
		Ok(())
	}
}
