//! `keetanetwork-vote` surface.
//!
//! [`Vote`] and [`VoteStaple`] are opaque handles around their decoded,
//! verified core types. Wire-native values are projected to FFI-native shapes
//! at the boundary: hashes become uppercase hex, `BigInt` serials become
//! decimal strings, issuers become their public-key string, and validity
//! endpoints become Unix milliseconds. Staple decode is moment-relative, so
//! [`VoteStaple::from_bytes`] takes the validation moment as Unix milliseconds.

use std::sync::Arc;

use keetanetwork_block::BlockTime;
use keetanetwork_vote::{ValidationConfig, Vote as CoreVote, VoteStaple as CoreVoteStaple};

use crate::block::Block;
use crate::error::FfiError;

/// Code for a moment value that cannot be represented as a timestamp.
const INVALID_MOMENT: &str = "INVALID_MOMENT";

/// Opaque handle to a decoded, signature-verified vote.
#[derive(uniffi::Object)]
pub struct Vote(CoreVote);

impl Vote {
	/// Wrap an already-decoded core vote in a shared FFI handle.
	pub(crate) fn wrap(vote: CoreVote) -> Arc<Self> {
		Arc::new(Self(vote))
	}
}

#[uniffi::export]
impl Vote {
	/// Decode and verify vote DER bytes.
	#[uniffi::constructor]
	pub fn from_bytes(bytes: Vec<u8>) -> Result<Arc<Vote>, FfiError> {
		Ok(Vote::wrap(CoreVote::verify(bytes)?))
	}

	/// Serialized DER bytes as transmitted on the network.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// Vote hash as uppercase hex.
	pub fn hash_hex(&self) -> String {
		hex::encode_upper(self.0.hash().as_bytes())
	}

	/// The vote serial as a decimal string.
	pub fn serial(&self) -> String {
		self.0.serial().to_string()
	}

	/// The issuing representative as its public-key string.
	pub fn issuer(&self) -> String {
		self.0.issuer().to_string()
	}

	/// The block hashes covered by the vote, as uppercase hex.
	pub fn block_hashes(&self) -> Vec<String> {
		self.0
			.blocks()
			.iter()
			.map(|hash| hex::encode_upper(hash.as_bytes()))
			.collect()
	}

	/// Start of the validity window as Unix milliseconds.
	pub fn validity_from_ms(&self) -> i64 {
		self.0.validity().from.unix_millis()
	}

	/// End of the validity window as Unix milliseconds.
	pub fn validity_to_ms(&self) -> i64 {
		self.0.validity().to.unix_millis()
	}

	/// Whether this is a quote vote (fees present and `quote = true`).
	pub fn is_quote(&self) -> bool {
		self.0.is_quote()
	}

	/// Whether the vote declares a fee schedule.
	pub fn has_fees(&self) -> bool {
		self.0.fees().is_some()
	}
}

/// Opaque handle to a decoded, verified vote staple.
#[derive(uniffi::Object)]
pub struct VoteStaple(CoreVoteStaple);

#[uniffi::export]
impl VoteStaple {
	/// Decode and verify compressed staple bytes against the default
	/// validation configuration at `moment_ms` (Unix milliseconds).
	#[uniffi::constructor]
	pub fn from_bytes(bytes: Vec<u8>, moment_ms: i64) -> Result<Arc<VoteStaple>, FfiError> {
		let moment = BlockTime::from_unix_millis(moment_ms)
			.ok_or_else(|| FfiError::boundary(INVALID_MOMENT, "moment milliseconds out of range"))?;
		let staple = CoreVoteStaple::verify(bytes, ValidationConfig::default(), moment)?;
		Ok(Arc::new(VoteStaple(staple)))
	}

	/// Compressed wire bytes as transmitted between operators.
	pub fn to_bytes(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// Staple hash as uppercase hex.
	pub fn hash_hex(&self) -> String {
		hex::encode_upper(self.0.hash().as_bytes())
	}

	/// The canonical-ordered blocks endorsed by the staple.
	pub fn blocks(&self) -> Vec<Arc<Block>> {
		self.0.blocks().iter().cloned().map(Block::wrap).collect()
	}

	/// The canonical-ordered votes carried by the staple.
	pub fn votes(&self) -> Vec<Arc<Vote>> {
		self.0.votes().iter().cloned().map(Vote::wrap).collect()
	}

	/// The number of blocks endorsed by the staple.
	pub fn block_count(&self) -> u32 {
		self.0.blocks().len() as u32
	}

	/// The number of votes carried by the staple.
	pub fn vote_count(&self) -> u32 {
		self.0.votes().len() as u32
	}
}
