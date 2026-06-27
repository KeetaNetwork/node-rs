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

use alloc::vec::Vec;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use keetanetwork_account::cert::CertSigner;
use keetanetwork_block::{AccountRef, Block, BlockHash, BlockTime};
use num_bigint::BigInt;

use crate::error::{VoteError, VoteField};
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
	permanent: bool,
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

	/// Mark the vote permanent.
	///
	/// A permanent vote's `validityTo` is derived from `validityFrom` and set
	/// beyond the permanence threshold, so any explicit `validityTo` is ignored.
	/// Permanent votes may not carry fees.
	pub fn permanent(mut self) -> Self {
		self.permanent = true;
		self
	}

	/// Build an unsigned vote, validating that all required fields were
	/// populated.
	pub fn build_unsigned(self) -> Result<UnsignedVote, VoteError> {
		let serial = self
			.serial
			.ok_or(VoteError::BuilderMissingField { field: VoteField::Serial })?;
		let issuer = self
			.issuer
			.ok_or(VoteError::BuilderMissingField { field: VoteField::Issuer })?;
		let from = self
			.validity_from
			.ok_or(VoteError::BuilderMissingField { field: VoteField::Validity })?;
		let to = if self.permanent {
			if self.fees.is_some() {
				return Err(VoteError::MalformedFeesInPermanentVote);
			}
			permanent_validity_to(from)?
		} else {
			self.validity_to
				.ok_or(VoteError::BuilderMissingField { field: VoteField::Validity })?
		};
		let validity = Validity::try_new(from, to)?;

		UnsignedVote::try_new(serial, issuer, validity, self.blocks, self.fees)
	}

	/// Build and sign with the supplied signer in a single call.
	pub fn build_signed(self, signer: &(impl CertSigner + ?Sized)) -> Result<Vote, VoteError> {
		self.build_unsigned()?.sign(signer)
	}
}

/// Compute the `validityTo` for a permanent vote from its `validityFrom`.
fn permanent_validity_to(from: BlockTime) -> Result<BlockTime, VoteError> {
	let base = DateTime::<Utc>::from_timestamp_millis(from.unix_millis()).ok_or(VoteError::InvalidValidity)?;
	let to = Utc
		.with_ymd_and_hms(base.year() + 1001, 1, 31, 0, 0, 0)
		.single()
		.ok_or(VoteError::InvalidValidity)?;
	BlockTime::from_unix_millis(to.timestamp_millis()).ok_or(VoteError::InvalidValidity)
}

/// Generate fluent setters on [`VoteQuoteBuilder`] that forward, by value,
/// to the wrapped [`VoteBuilder`].
macro_rules! forward_to_inner {
	($( $(#[$meta:meta])* $name:ident($($arg:ident: $ty:ty),*) ),* $(,)?) => {
		$(
			$(#[$meta])*
			pub fn $name(mut self, $($arg: $ty),*) -> Self {
				self.inner = self.inner.$name($($arg),*);
				self
			}
		)*
	};
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

	forward_to_inner! {
		/// Set the serial number.
		serial(serial: impl Into<BigInt>),
		/// Set the issuing representative.
		issuer(issuer: AccountRef),
		/// Set the validity range.
		validity(from: BlockTime, to: BlockTime),
		/// Append a single block hash.
		add_block(hash: BlockHash),
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
	///
	/// A quote negotiates fees, so omitting the fee schedule is a builder
	/// error rather than a fee-less vote.
	pub fn build(self, signer: &(impl CertSigner + ?Sized)) -> Result<VoteQuote, VoteError> {
		if self.inner.fees.is_none() {
			return Err(VoteError::FeeQuoteMissingFees);
		}

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
		#[cfg(feature = "std")]
		let moment = self.moment.unwrap_or_else(BlockTime::now);
		#[cfg(not(feature = "std"))]
		let moment = self.moment.ok_or(VoteError::MissingMoment)?;
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
		assert!(matches!(result, Err(VoteError::BuilderMissingField { field: VoteField::Serial })));
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
		use crate::testing::single_fees;

		let issuer = ed25519_issuer(b"alice");
		let (from, to) = one_minute_validity();
		let quote = VoteQuoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity(from, to)
			.add_block(BlockHash::from([1u8; 32]))
			.fees(single_fees(1))
			.build(issuer.as_ref())?;
		assert!(quote.as_vote().is_quote());
		Ok(())
	}

	#[test]
	fn test_vote_quote_builder_rejects_missing_fees() {
		let issuer = ed25519_issuer(b"alice");
		let (from, to) = one_minute_validity();
		let result = VoteQuoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity(from, to)
			.add_block(BlockHash::from([1u8; 32]))
			.build(issuer.as_ref());
		assert!(matches!(result, Err(VoteError::FeeQuoteMissingFees)));
	}

	#[test]
	fn test_permanent_vote_builder_is_permanent() -> Result<(), VoteError> {
		let issuer = ed25519_issuer(b"alice");
		let vote = VoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity_from(moment(0))
			.add_block(BlockHash::from([1u8; 32]))
			.permanent()
			.build_signed(issuer.as_ref())?;
		assert!(vote.is_permanent_at(moment(0), ValidationConfig::default()));
		Ok(())
	}

	#[test]
	fn test_permanent_vote_builder_rejects_fees() {
		use crate::testing::single_fees;

		let issuer = ed25519_issuer(b"alice");
		let result = VoteBuilder::new()
			.serial(BigInt::from(7u8))
			.issuer(issuer.clone())
			.validity_from(moment(0))
			.add_block(BlockHash::from([1u8; 32]))
			.fees(single_fees(1))
			.permanent()
			.build_unsigned();
		assert!(matches!(result, Err(VoteError::MalformedFeesInPermanentVote)));
	}
}
