//! Vote validity period and the moment-based predicates that act on it.
//!
//! Every vote declares two timestamps:
//!
//! * `validity_from` - the earliest instant at which the issuer considers
//!   the vote valid.
//! * `validity_to` - the instant past which the vote is no longer valid.
//!
//! Both are stored as [`BlockTime`] (millisecond-precision unix time) and
//! travel on the wire as ASN.1 `GeneralizedTime`.
//!
//! ## Predicates
//!
//! Three queries operate on a [`Validity`] and a check moment:
//!
//! * [`Validity::range_is_well_formed`] - `validity_from <= validity_to`.
//! * [`Validity::is_expired_at`] - the moment falls outside the window,
//!   after symmetric slop tolerance is applied at both endpoints.
//! * [`Validity::is_permanent_at`] - `validity_to` exceeds the moment by
//!   more than the configured threshold (see
//!   [`crate::ValidationConfig`]). Permanent votes are bundled into
//!   different staples than temporary ones.
//!
//! Slop tolerance and the permanence threshold both come from
//! [`ValidationConfig`]; the same vote can be temporary under one
//! configuration and permanent under another.

use keetanetwork_block::BlockTime;

use crate::error::VoteError;
use crate::validation::ValidationConfig;

/// Validity range of a vote, inclusive on both endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
	/// First instant at which the vote is valid.
	pub from: BlockTime,
	/// Last instant at which the vote is valid.
	pub to: BlockTime,
}

impl Validity {
	/// Construct a validity range, returning [`VoteError::InvalidValidity`]
	/// when the range is not well-formed.
	pub fn try_new(from: BlockTime, to: BlockTime) -> Result<Self, VoteError> {
		let validity = Self { from, to };
		if !validity.range_is_well_formed() {
			return Err(VoteError::InvalidValidity);
		}
		Ok(validity)
	}

	/// Whether `validity_from <= validity_to`.
	pub fn range_is_well_formed(&self) -> bool {
		self.from.unix_millis() <= self.to.unix_millis()
	}

	/// Whether the vote is expired at `moment` under the supplied
	/// configuration.
	///
	/// Returns `true` when `moment + slop < validity_from` *or*
	/// `moment - slop > validity_to`. The slop tolerance is applied
	/// symmetrically so that minor clock skew between operators does not
	/// cause spurious rejections at either endpoint.
	pub fn is_expired_at(&self, moment: BlockTime, config: ValidationConfig) -> bool {
		let now = moment.unix_millis();
		let from = self.from.unix_millis();
		let to = self.to.unix_millis();
		now.saturating_add(config.allowed_slop_ms) < from || now.saturating_sub(config.allowed_slop_ms) > to
	}

	/// Whether `moment` falls before `validity_from` even after applying the
	/// slop tolerance.
	pub fn moment_is_before_from(&self, moment: BlockTime, config: ValidationConfig) -> bool {
		moment.unix_millis()
			< self
				.from
				.unix_millis()
				.saturating_sub(config.allowed_slop_ms)
	}

	/// Whether the vote should be considered permanent at `moment` under the
	/// supplied configuration.
	pub fn is_permanent_at(&self, moment: BlockTime, config: ValidationConfig) -> bool {
		self.to.unix_millis()
			> moment
				.unix_millis()
				.saturating_add(config.permanent_vote_threshold_ms)
	}
}

impl TryFrom<(BlockTime, BlockTime)> for Validity {
	type Error = VoteError;

	fn try_from((from, to): (BlockTime, BlockTime)) -> Result<Self, Self::Error> {
		Self::try_new(from, to)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn moment(ms: i64) -> BlockTime {
		BlockTime::from_unix_millis(ms).expect("moment construction must succeed")
	}

	fn validity(from_ms: i64, to_ms: i64) -> Validity {
		Validity::try_new(moment(from_ms), moment(to_ms)).expect("validity range must be well-formed")
	}

	#[test]
	fn test_range_well_formed() {
		assert!(validity(1_000, 2_000).range_is_well_formed());
		let result = Validity::try_new(moment(2_000), moment(1_000));
		assert!(matches!(result, Err(VoteError::InvalidValidity)));
	}

	#[test]
	fn test_expired_within_window() {
		assert!(!validity(1_000, 2_000).is_expired_at(moment(1_500), ValidationConfig::default()));
	}

	#[test]
	fn test_expired_after_window_with_slop() {
		let v = validity(0, 1_000);
		let config = ValidationConfig::default();
		// Default slop is 60 000 ms; 60 999 still inside slop window.
		assert!(!v.is_expired_at(moment(60_999), config));
		// 61 001 is one millisecond past the slop tolerance.
		assert!(v.is_expired_at(moment(61_001), config));
	}

	#[test]
	fn test_moment_before_from() {
		let v = validity(60_000, 120_000);
		let config = ValidationConfig::default();
		assert!(!v.moment_is_before_from(moment(0), config));
		assert!(v.moment_is_before_from(moment(-1_000), config));
	}

	#[test]
	fn test_permanent_threshold() {
		let permanent = validity(0, ValidationConfig::DEFAULT_PERMANENT_THRESHOLD_MS + 1);
		let config = ValidationConfig::default();
		assert!(permanent.is_permanent_at(moment(0), config));

		let temp = validity(0, 1_000);
		assert!(!temp.is_permanent_at(moment(0), config));
	}

	#[test]
	fn test_try_from_tuple_matches_try_new() -> Result<(), VoteError> {
		let from = moment(1_000);
		let to = moment(2_000);
		assert_eq!(Validity::try_from((from, to))?, Validity::try_new(from, to)?);
		assert!(matches!(Validity::try_from((to, from)), Err(VoteError::InvalidValidity)));
		Ok(())
	}
}
