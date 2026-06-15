//! Network-parameterized validation configuration for votes.
//!
//! [`ValidationConfig`] holds the two tunable parameters that vote
//! validation consults at every check:
//!
//! * `allowed_slop_ms` - symmetric wall-clock skew tolerance applied at
//!   both ends of a vote's validity window. Defaults to 60 seconds.
//! * `permanent_vote_threshold_ms` - if `validity_to` exceeds the check
//!   moment by more than this, the vote is treated as permanent. Permanent
//!   votes may not carry fees and are bundled into separate staples from
//!   temporary ones. Defaults to ≈100 years (365-day years).
//!
//! `From<Network>` returns the defaults for every network today; the trait
//! is the extension point for per-network tuning if that ever becomes
//! necessary.

pub use keetanetwork_block::Network;

/// Per-network parameters for vote validation.
#[derive(Debug, Clone, Copy)]
pub struct ValidationConfig {
	/// Wall-clock skew tolerance, in milliseconds.
	pub allowed_slop_ms: i64,
	/// Threshold beyond which a vote is treated as permanent, in milliseconds.
	pub permanent_vote_threshold_ms: i64,
}

impl ValidationConfig {
	/// 60 seconds, in milliseconds.
	pub const DEFAULT_SLOP_MS: i64 = 60 * 1000;
	/// 100 years, in milliseconds (using a 365-day year).
	pub const DEFAULT_PERMANENT_THRESHOLD_MS: i64 = 100 * 365 * 86_400 * 1000;
}

impl Default for ValidationConfig {
	fn default() -> Self {
		Self {
			allowed_slop_ms: Self::DEFAULT_SLOP_MS,
			permanent_vote_threshold_ms: Self::DEFAULT_PERMANENT_THRESHOLD_MS,
		}
	}
}

impl From<Network> for ValidationConfig {
	fn from(_network: Network) -> Self {
		// All networks currently share the same validation parameters.
		// The conversion exists so per-network tuning can be introduced
		// later without breaking the construction surface.
		Self::default()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_defaults_match_reference_constants() {
		let config = ValidationConfig::default();
		assert_eq!(config.allowed_slop_ms, 60_000);
		assert_eq!(config.permanent_vote_threshold_ms, 100i64 * 365 * 86_400 * 1000);
	}

	#[test]
	fn test_from_network_uses_defaults() {
		let config = ValidationConfig::from(Network::Test);
		assert_eq!(config.allowed_slop_ms, ValidationConfig::DEFAULT_SLOP_MS);
		assert_eq!(config.permanent_vote_threshold_ms, ValidationConfig::DEFAULT_PERMANENT_THRESHOLD_MS);
	}
}
