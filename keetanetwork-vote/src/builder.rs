//! Fluent builders for [`Vote`], [`VoteQuote`], and [`VoteStaple`].
//!
//! - [`VoteBuilder`] - builds an [`UnsignedVote`] via
//!   [`VoteBuilder::build_unsigned`] or signs in one step via
//!   [`VoteBuilder::build_signed`].
//! - [`VoteQuoteBuilder`] - wraps [`VoteBuilder`] and forces
//!   `quote = true` on the fee schedule, producing a [`VoteQuote`].
//! - [`VoteStapleBuilder`] - collects [`Vote`]s and [`Block`]s and
//!   applies canonical ordering + staple invariants on
//!   [`VoteStapleBuilder::build`].

use keetanetwork_account::cert::CertSigner;
use keetanetwork_block::{AccountRef, Block, BlockHash, BlockTime};
use num_bigint::BigInt;

use crate::error::VoteError;
use crate::fee::Fees;
use crate::staple::VoteStaple;
use crate::validation::ValidationConfig;
use crate::validity::Validity;
use crate::vote::{UnsignedVote, Vote, VoteQuote};

/// Fluent builder for an [`UnsignedVote`].
#[derive(Debug, Default, Clone)]
pub struct VoteBuilder {
	serial: Option<BigInt>,
	issuer: Option<AccountRef>,
	validity_from: Option<BlockTime>,
	validity_to: Option<BlockTime>,
	blocks: Vec<BlockHash>,
	fees: Option<Fees>,
}

impl VoteBuilder {
	/// Create a fresh builder with no fields set.
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the serial number of the vote.
	pub fn serial(mut self, serial: impl Into<BigInt>) -> Self {
		self.serial = Some(serial.into());
		self
	}

	/// Set the issuing representative.
	pub fn issuer(mut self, issuer: AccountRef) -> Self {
		self.issuer = Some(issuer);
		self
	}

	/// Set the validity range.
	pub fn validity(mut self, from: BlockTime, to: BlockTime) -> Self {
		self.validity_from = Some(from);
		self.validity_to = Some(to);
		self
	}

	/// Override `validityFrom` independently of `validityTo`.
	pub fn validity_from(mut self, from: BlockTime) -> Self {
		self.validity_from = Some(from);
		self
	}

	/// Override `validityTo` independently of `validityFrom`.
	pub fn validity_to(mut self, to: BlockTime) -> Self {
		self.validity_to = Some(to);
		self
	}

	/// Append a single block hash to the vote.
	pub fn add_block(mut self, hash: BlockHash) -> Self {
		self.blocks.push(hash);
		self
	}

	/// Append multiple block hashes (preserving caller order).
	pub fn add_blocks<I>(mut self, hashes: I) -> Self
	where
		I: IntoIterator<Item = BlockHash>,
	{
		self.blocks.extend(hashes);
		self
	}

	/// Attach a fees extension. Setting fees with `quote = true` produces a
	/// vote that must be wrapped via [`VoteQuoteBuilder`].
	pub fn fees(mut self, fees: Fees) -> Self {
		self.fees = Some(fees);
		self
	}

	/// Build an unsigned vote, validating that all required fields were
	/// populated.
	pub fn build_unsigned(self) -> Result<UnsignedVote, VoteError> {
		let serial = self.serial.ok_or(VoteError::BuilderInvalidSerial)?;
		let issuer = self.issuer.ok_or(VoteError::BuilderInvalidConstruction)?;
		let from = self
			.validity_from
			.ok_or(VoteError::BuilderInvalidValidToFrom)?;
		let to = self
			.validity_to
			.ok_or(VoteError::BuilderInvalidValidToFrom)?;
		let validity = Validity::try_new(from, to)?;

		UnsignedVote::try_new(serial, issuer, validity, self.blocks, self.fees)
	}

	/// Build and sign with the supplied signer in a single call.
	pub fn build_signed(self, signer: &(impl CertSigner + ?Sized)) -> Result<Vote, VoteError> {
		self.build_unsigned()?.sign(signer)
	}
}

/// Builder that produces a [`VoteQuote`].
///
/// Internally wraps [`VoteBuilder`] but injects `quote = true` into the fees
/// extension and enforces the quote-vote invariant at build time.
#[derive(Debug, Default, Clone)]
pub struct VoteQuoteBuilder {
	inner: VoteBuilder,
}

impl VoteQuoteBuilder {
	/// Create an empty quote builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Set the serial number.
	pub fn serial(mut self, serial: impl Into<BigInt>) -> Self {
		self.inner = self.inner.serial(serial);
		self
	}

	/// Set the issuing representative.
	pub fn issuer(mut self, issuer: AccountRef) -> Self {
		self.inner = self.inner.issuer(issuer);
		self
	}

	/// Set the validity range.
	pub fn validity(mut self, from: BlockTime, to: BlockTime) -> Self {
		self.inner = self.inner.validity(from, to);
		self
	}

	/// Append a single block hash.
	pub fn add_block(mut self, hash: BlockHash) -> Self {
		self.inner = self.inner.add_block(hash);
		self
	}

	/// Append multiple block hashes.
	pub fn add_blocks<I>(mut self, hashes: I) -> Self
	where
		I: IntoIterator<Item = BlockHash>,
	{
		self.inner = self.inner.add_blocks(hashes);
		self
	}

	/// Attach the fee schedule. The builder will rewrite `quote` to `true`
	/// regardless of the input value.
	pub fn fees(mut self, fees: Fees) -> Self {
		let normalized = match fees {
			Fees::Single { fee, .. } => Fees::Single { quote: true, fee },
			Fees::Multiple { fees, .. } => Fees::Multiple { quote: true, fees },
		};
		self.inner = self.inner.fees(normalized);
		self
	}

	/// Build and sign the quote in a single call.
	pub fn build(self, signer: &(impl CertSigner + ?Sized)) -> Result<VoteQuote, VoteError> {
		let vote = self.inner.build_signed(signer)?;
		VoteQuote::try_from_vote(vote)
	}
}

/// Fluent builder for a [`VoteStaple`].
#[derive(Debug, Clone, Default)]
pub struct VoteStapleBuilder {
	blocks: Vec<Block>,
	votes: Vec<Vote>,
	moment: Option<BlockTime>,
	config: ValidationConfig,
}

impl VoteStapleBuilder {
	/// Create an empty staple builder.
	pub fn new() -> Self {
		Self::default()
	}

	/// Add a block to the staple.
	pub fn add_block(mut self, block: Block) -> Self {
		self.blocks.push(block);
		self
	}

	/// Add multiple blocks to the staple.
	pub fn add_blocks<I>(mut self, blocks: I) -> Self
	where
		I: IntoIterator<Item = Block>,
	{
		self.blocks.extend(blocks);
		self
	}

	/// Add a vote to the staple.
	pub fn add_vote(mut self, vote: Vote) -> Self {
		self.votes.push(vote);
		self
	}

	/// Add multiple votes to the staple.
	pub fn add_votes<I>(mut self, votes: I) -> Self
	where
		I: IntoIterator<Item = Vote>,
	{
		self.votes.extend(votes);
		self
	}

	/// Override the validation configuration; defaults to
	/// [`ValidationConfig::default`].
	pub fn config(mut self, config: ValidationConfig) -> Self {
		self.config = config;
		self
	}

	/// Set the validation moment used for permanence and expiry checks.
	pub fn moment(mut self, moment: BlockTime) -> Self {
		self.moment = Some(moment);
		self
	}

	/// Build the staple, applying canonical ordering and invariants.
	pub fn build(self) -> Result<VoteStaple, VoteError> {
		let moment = self.moment.unwrap_or_else(BlockTime::now);
		VoteStaple::try_new(self.blocks, self.votes, self.config, moment)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::testing::{ed25519_issuer, moment};

	fn one_minute_validity() -> (BlockTime, BlockTime) {
		(moment(0), moment(60_000))
	}

	#[test]
	fn test_vote_builder_requires_serial() {
		let issuer = ed25519_issuer(b"alice");
		let (from, to) = one_minute_validity();
		let result = VoteBuilder::new()
			.issuer(issuer)
			.validity(from, to)
			.add_block(BlockHash::from([1u8; 32]))
			.build_unsigned();
		assert!(matches!(result, Err(VoteError::BuilderInvalidSerial)));
	}

	#[test]
	fn test_vote_builder_round_trip_signed() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let (from, to) = one_minute_validity();
		let vote = VoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity(from, to)
			.add_block(BlockHash::from([1u8; 32]))
			.build_signed(issuer.as_ref())?;
		assert_eq!(vote.serial(), &BigInt::from(7u8));
		Ok(())
	}

	#[test]
	fn test_vote_quote_builder_forces_quote_flag() -> Result<(), VoteError> {
		use keetanetwork_block::Amount;

		use crate::fee::Fee;

		let issuer = ed25519_issuer(b"alice");
		let (from, to) = one_minute_validity();
		let quote = VoteQuoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity(from, to)
			.add_block(BlockHash::from([1u8; 32]))
			.fees(Fees::Single { quote: false, fee: Fee { amount: Amount::from(1u64), pay_to: None, token: None } })
			.build(issuer.as_ref())?;
		assert!(quote.as_vote().is_quote());
		Ok(())
	}
}
