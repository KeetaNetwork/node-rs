//! Vote staple - a zlib-compressed bundle of blocks and votes.
//!
//! A [`VoteStaple`] is the unit of cross-operator gossip for confirmed
//! work: one or more votes endorsing the same set of blocks, transmitted
//! together so a peer can reach the same conclusion as the originator
//! without having to look any constituent piece up separately.
//!
//! ## Transport Format
//!
//! ```text
//! StapleBundle ::= SEQUENCE {
//!     blocks  SEQUENCE OF OCTET STRING,
//!     votes   SEQUENCE OF OCTET STRING
//! }
//! ```
//!
//! The bundle is encoded as DER and then deflated with zlib. The deflated
//! stream is the artifact transmitted between operators and the value
//! returned by [`VoteStaple::as_bytes`]; the uncompressed form is hashed
//! to produce the staple's [`crate::VoteStapleHash`].
//!
//! ## Canonical Ordering
//!
//! [`VoteStaple::try_new`] reorders the supplied blocks to match the
//! representative vote's block list and sorts votes by the big-endian
//! numeric interpretation of their hash. The resulting wire bytes are
//! deterministic for any input set, so two operators handed the same
//! `(blocks, votes)` produce byte-identical staples and identical hashes.

use std::io::{Read, Write};

use der::{Reader, SliceReader};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use keetanetwork_block::{Block, BlockHash, BlockTime, Hashable};
use num_bigint::BigInt;

use crate::error::VoteError;
use crate::hash::{VoteBlockHash, VoteStapleHash};
use crate::validation::ValidationConfig;
use crate::vote::Vote;
use crate::wire::{encode_octet, read_octet, read_sequence, wrap_sequence};

/// A bundle of blocks and the votes endorsing them.
#[derive(Debug, Clone)]
pub struct VoteStaple {
	blocks: Vec<Block>,
	votes: Vec<Vote>,
	/// Cached deflated wire bytes.
	compressed_bytes: Vec<u8>,
	/// Cached uncompressed canonical SEQUENCE bytes (used for hashing).
	canonical_bytes: Vec<u8>,
}

impl VoteStaple {
	/// Build a staple from the provided blocks and votes, enforcing
	/// canonical ordering and the staple invariants.
	///
	/// * `blocks` are reordered to match the representative vote's block
	///   list so the wire bytes are deterministic.
	/// * `votes` are sorted by the big-endian numeric interpretation of
	///   their hash.
	pub fn try_new(
		blocks: impl IntoIterator<Item = Block>,
		votes: impl IntoIterator<Item = Vote>,
		config: ValidationConfig,
		moment: BlockTime,
	) -> Result<Self, VoteError> {
		let mut blocks: Vec<Block> = blocks.into_iter().collect();
		let mut votes: Vec<Vote> = votes.into_iter().collect();

		if votes.is_empty() {
			return Err(VoteError::StapleVotesAtLeastOne);
		}
		if blocks.is_empty() {
			return Err(VoteError::StapleBlocksAtLeastOne);
		}

		validate_vote_invariants(&votes, config, moment)?;

		let representative = votes.first().ok_or(VoteError::StapleVotesAtLeastOne)?;
		let representative_blocks: Vec<BlockHash> = representative.blocks().to_vec();
		reorder_blocks_to_match(&mut blocks, &representative_blocks)?;

		votes.sort_by(compare_votes_by_hash);

		let canonical_bytes = encode_canonical(&blocks, &votes)?;
		let compressed_bytes = deflate(&canonical_bytes)?;

		Ok(Self { blocks, votes, compressed_bytes, canonical_bytes })
	}

	/// Decode and verify a staple from its compressed wire bytes.
	pub fn verify(bytes: impl Into<Vec<u8>>, config: ValidationConfig, moment: BlockTime) -> Result<Self, VoteError> {
		let compressed = bytes.into();
		let canonical_bytes = inflate(&compressed)?;
		let (blocks, votes) = decode_canonical(&canonical_bytes)?;

		if votes.is_empty() {
			return Err(VoteError::StapleVotesAtLeastOne);
		}
		if blocks.is_empty() {
			return Err(VoteError::StapleBlocksAtLeastOne);
		}

		validate_vote_invariants(&votes, config, moment)?;

		// Re-encode to ensure canonical ordering was honoured by the input.
		let representative_blocks: Vec<BlockHash> = votes
			.first()
			.ok_or(VoteError::StapleVotesAtLeastOne)?
			.blocks()
			.to_vec();
		assert_block_order(&blocks, &representative_blocks)?;
		assert_vote_order(&votes)?;

		Ok(Self { blocks, votes, compressed_bytes: compressed, canonical_bytes })
	}

	/// Compressed wire bytes (the form transmitted between operators).
	pub fn as_bytes(&self) -> &[u8] {
		&self.compressed_bytes
	}

	/// SHA3-256 hash of the canonical (uncompressed) staple bytes.
	pub fn hash(&self) -> VoteStapleHash {
		VoteStapleHash::of(&self.canonical_bytes)
	}

	/// Hash derived from the block hashes in this staple - equivalent to
	/// `VoteBlockHash::from_block_hashes(self.block_hashes())`.
	pub fn block_hash(&self) -> VoteBlockHash {
		let hashes: Vec<BlockHash> = self.blocks.iter().map(|block| block.hash()).collect();
		VoteBlockHash::from_block_hashes(hashes)
	}

	/// Slice of canonical-ordered blocks.
	pub fn blocks(&self) -> &[Block] {
		&self.blocks
	}

	/// Slice of canonical-ordered votes.
	pub fn votes(&self) -> &[Vote] {
		&self.votes
	}
}

impl AsRef<[u8]> for VoteStaple {
	fn as_ref(&self) -> &[u8] {
		self.as_bytes()
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_vote_invariants(votes: &[Vote], config: ValidationConfig, moment: BlockTime) -> Result<(), VoteError> {
	let representative = votes.first().ok_or(VoteError::StapleVotesAtLeastOne)?;
	let expected_blocks = representative.blocks();
	let representative_permanent = representative.is_permanent_at(moment, config);

	let mut seen_issuers: Vec<Vec<u8>> = Vec::with_capacity(votes.len());

	for vote in votes {
		if vote.blocks().len() != expected_blocks.len() {
			return Err(VoteError::StapleBlockCountMismatch);
		}
		for (left, right) in vote.blocks().iter().zip(expected_blocks) {
			if left != right {
				return Err(VoteError::StapleBlockOrderMismatch);
			}
		}
		if vote.is_permanent_at(moment, config) != representative_permanent {
			return Err(VoteError::StaplePermanenceMismatch);
		}
		let issuer_bytes = vote.issuer().to_public_key_with_type();
		if seen_issuers
			.iter()
			.any(|existing| existing == &issuer_bytes)
		{
			return Err(VoteError::StapleDuplicateIssuer);
		}
		seen_issuers.push(issuer_bytes);
	}
	Ok(())
}

fn reorder_blocks_to_match(blocks: &mut Vec<Block>, expected: &[BlockHash]) -> Result<(), VoteError> {
	let mut reordered: Vec<Option<Block>> = (0..expected.len()).map(|_| None).collect();
	for block in blocks.drain(..) {
		let position = expected
			.iter()
			.position(|hash| *hash == block.hash())
			.ok_or(VoteError::StapleMissingBlock)?;
		if reordered[position].is_some() {
			return Err(VoteError::StapleMissingBlock);
		}
		reordered[position] = Some(block);
	}
	let mut output = Vec::with_capacity(reordered.len());
	for slot in reordered {
		output.push(slot.ok_or(VoteError::StapleMissingBlock)?);
	}
	*blocks = output;
	Ok(())
}

fn assert_block_order(blocks: &[Block], expected: &[BlockHash]) -> Result<(), VoteError> {
	if blocks.len() != expected.len() {
		return Err(VoteError::StapleBlockCountMismatch);
	}
	for (block, hash) in blocks.iter().zip(expected) {
		if block.hash() != *hash {
			return Err(VoteError::StapleBlockOrderMismatch);
		}
	}
	Ok(())
}

fn assert_vote_order(votes: &[Vote]) -> Result<(), VoteError> {
	let mut prev: Option<BigInt> = None;
	for vote in votes {
		let current = vote_hash_as_bigint(vote);
		if let Some(previous) = &prev {
			if &current < previous {
				return Err(VoteError::StapleInvalidConstruction);
			}
		}
		prev = Some(current);
	}
	Ok(())
}

fn compare_votes_by_hash(a: &Vote, b: &Vote) -> core::cmp::Ordering {
	vote_hash_as_bigint(a).cmp(&vote_hash_as_bigint(b))
}

fn vote_hash_as_bigint(vote: &Vote) -> BigInt {
	BigInt::from_bytes_be(num_bigint::Sign::Plus, vote.hash().as_bytes())
}

// ---------------------------------------------------------------------------
// Wire codec
// ---------------------------------------------------------------------------

fn encode_canonical(blocks: &[Block], votes: &[Vote]) -> Result<Vec<u8>, VoteError> {
	let mut blocks_content = Vec::new();
	for block in blocks {
		encode_octet(&mut blocks_content, block.to_bytes())?;
	}
	let blocks_sequence = wrap_sequence(&blocks_content)?;

	let mut votes_content = Vec::new();
	for vote in votes {
		encode_octet(&mut votes_content, vote.as_bytes())?;
	}
	let votes_sequence = wrap_sequence(&votes_content)?;

	let mut content = Vec::new();
	content.extend_from_slice(&blocks_sequence);
	content.extend_from_slice(&votes_sequence);
	wrap_sequence(&content)
}

fn decode_canonical(bytes: &[u8]) -> Result<(Vec<Block>, Vec<Vote>), VoteError> {
	let mut outer = SliceReader::new(bytes).map_err(|_| VoteError::MalformedStaple)?;
	let inner = read_sequence(&mut outer).map_err(|_| VoteError::MalformedStaple)?;
	if !outer.is_finished() {
		return Err(VoteError::MalformedStaple);
	}
	let mut inner_reader = SliceReader::new(inner).map_err(|_| VoteError::MalformedStaple)?;

	let blocks_inner =
		read_sequence(&mut inner_reader).map_err(|_| VoteError::MalformedStapleElement { what: "blocks" })?;
	let mut blocks_reader =
		SliceReader::new(blocks_inner).map_err(|_| VoteError::MalformedStapleElement { what: "blocks" })?;
	let mut blocks = Vec::new();
	while !blocks_reader.is_finished() {
		let raw = read_octet(&mut blocks_reader).map_err(|_| VoteError::MalformedStapleElement { what: "blocks" })?;
		let block = Block::try_from(raw)?;
		blocks.push(block);
	}

	let votes_inner =
		read_sequence(&mut inner_reader).map_err(|_| VoteError::MalformedStapleElement { what: "votes" })?;
	let mut votes_reader =
		SliceReader::new(votes_inner).map_err(|_| VoteError::MalformedStapleElement { what: "votes" })?;
	let mut votes = Vec::new();
	while !votes_reader.is_finished() {
		let raw = read_octet(&mut votes_reader).map_err(|_| VoteError::MalformedStapleElement { what: "votes" })?;
		votes.push(Vote::verify(raw.to_vec())?);
	}

	if !inner_reader.is_finished() {
		return Err(VoteError::MalformedStaple);
	}

	Ok((blocks, votes))
}

fn deflate(input: &[u8]) -> Result<Vec<u8>, VoteError> {
	let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
	encoder.write_all(input)?;
	Ok(encoder.finish()?)
}

fn inflate(input: &[u8]) -> Result<Vec<u8>, VoteError> {
	let mut decoder = ZlibDecoder::new(input);
	let mut output = Vec::new();
	decoder.read_to_end(&mut output)?;
	Ok(output)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_deflate_inflate_round_trip() -> Result<(), VoteError> {
		let payload = b"keetanetwork vote staple test payload";
		let deflated = deflate(payload)?;
		let inflated = inflate(&deflated)?;
		assert_eq!(inflated, payload);
		Ok(())
	}

	#[test]
	fn test_inflate_rejects_garbage() {
		let result = inflate(&[0xFFu8; 16]);
		assert!(result.is_err());
	}
}
