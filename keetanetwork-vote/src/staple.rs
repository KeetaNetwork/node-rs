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
//! numeric interpretation of their hash.

use alloc::vec::Vec;

use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec_zlib;

use keetanetwork_asn1::vote as transport;
use keetanetwork_block::{Block, BlockHash, BlockTime};
use keetanetwork_crypto::verify::Verifiable;

use crate::error::VoteError;
use crate::hash::{Hashable, VoteBlockHash, VoteStapleHash};
use crate::validation::ValidationConfig;
use crate::vote::Vote;

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

impl Verifiable for VoteStaple {
	type Context = (ValidationConfig, BlockTime);
	type Error = VoteError;

	fn verify(bytes: impl Into<Vec<u8>>, (config, moment): Self::Context) -> Result<Self, VoteError> {
		VoteStaple::verify(bytes, config, moment)
	}
}

impl Hashable for VoteStaple {
	type Digest = VoteStapleHash;

	fn hash(&self) -> Self::Digest {
		VoteStaple::hash(self)
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
	let mut prev = None;
	for vote in votes {
		let current = vote.hash();
		if let Some(previous) = prev {
			if current < previous {
				return Err(VoteError::StapleInvalidConstruction);
			}
		}

		prev = Some(current);
	}

	Ok(())
}

// A vote hash is a fixed-size 32-byte big-endian digest, so lexicographic
// byte ordering coincides with its unsigned numeric interpretation.
fn compare_votes_by_hash(a: &Vote, b: &Vote) -> core::cmp::Ordering {
	a.hash().cmp(&b.hash())
}

// ---------------------------------------------------------------------------
// Transport codec
// ---------------------------------------------------------------------------

fn encode_canonical(blocks: &[Block], votes: &[Vote]) -> Result<Vec<u8>, VoteError> {
	let bundle = transport::VoteStapleBundle {
		blocks: blocks
			.iter()
			.map(|block| block.to_bytes().to_vec())
			.collect(),
		votes: votes.iter().map(|vote| vote.as_bytes().to_vec()).collect(),
	};
	transport::encode_vote_staple(&bundle).map_err(VoteError::from)
}

fn decode_canonical(bytes: &[u8]) -> Result<(Vec<Block>, Vec<Vote>), VoteError> {
	let bundle = transport::decode_vote_staple(bytes).map_err(staple_decode_error)?;
	let mut blocks = Vec::with_capacity(bundle.blocks.len());
	for raw in bundle.blocks {
		blocks.push(Block::try_from(raw.as_slice())?);
	}

	let mut votes = Vec::with_capacity(bundle.votes.len());
	for raw in bundle.votes {
		votes.push(Vote::verify(raw)?);
	}

	Ok((blocks, votes))
}

fn staple_decode_error(error: keetanetwork_asn1::Asn1Error) -> VoteError {
	use keetanetwork_asn1::vote::VoteStapleDecodeSlot;
	use keetanetwork_asn1::Asn1Error;
	match error {
		Asn1Error::VoteStapleDecode { slot: VoteStapleDecodeSlot::Blocks } => {
			VoteError::MalformedStapleElement { what: "blocks" }
		}
		Asn1Error::VoteStapleDecode { slot: VoteStapleDecodeSlot::Votes } => {
			VoteError::MalformedStapleElement { what: "votes" }
		}
		_ => VoteError::MalformedStaple,
	}
}

// `compress_to_vec_zlib`'s level argument follows the zlib convention (0-10)
const ZLIB_DEFAULT_LEVEL: u8 = 6;

fn deflate(input: &[u8]) -> Result<Vec<u8>, VoteError> {
	Ok(compress_to_vec_zlib(input, ZLIB_DEFAULT_LEVEL))
}

fn inflate(input: &[u8]) -> Result<Vec<u8>, VoteError> {
	// Reference treats failed zlib inflation of a staple as a malformed
	// staple (with a fallback to raw bytes).
	decompress_to_vec_zlib(input).map_err(|_| VoteError::MalformedStaple)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::{block_hash, ed25519_issuer, moment, opening_block, sign_simple_vote, validity_millis};

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

	#[test]
	fn test_verifiable_matches_inherent_verify() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"rep");
		let block = opening_block(&ed25519_issuer(b"owner"), &ed25519_issuer(b"to"));
		let validity = validity_millis(0, 60_000);
		let vote = sign_simple_vote(&issuer, 1, validity, [block_hash(&block)], None);
		let config = ValidationConfig::default();
		let at = moment(0);

		let staple = VoteStaple::try_new([block], [vote], config, at)?;
		let decoded = <VoteStaple as Verifiable>::verify(staple.as_bytes().to_vec(), (config, at))?;
		assert_eq!(decoded.hash(), staple.hash());
		Ok(())
	}
}
