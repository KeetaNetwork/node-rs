//! These functions perform no I/O and depend only on `core` + `alloc`, so they
//! compile under `no_std` and can be reused by callers that drive their own
//! transport.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use num_bigint::BigInt;

/// Reliability after a successful dispatch: AIMD additive increase,
/// clamped to `1.0`.
#[must_use]
pub fn reliability_after_success(current: f64, increment: f64) -> f64 {
	(current + increment).min(1.0)
}

/// Reliability after a failed dispatch: AIMD multiplicative decrease, floored
/// to prevent an absorbing state.
#[must_use]
pub fn reliability_after_failure(current: f64, decay: f64, floor: f64) -> f64 {
	(current * decay).max(floor)
}

/// Compute `numerator / denominator` as an `f64`, scaling large values to
/// preserve precision. A zero denominator yields `0.0`.
#[must_use]
pub fn bigint_ratio(numerator: &BigInt, denominator: &BigInt) -> f64 {
	if denominator == &BigInt::from(0u8) {
		return 0.0;
	}

	let scale = BigInt::from(1_000_000_000u64);
	let scaled = (numerator * &scale) / denominator;
	bigint_to_f64(&scaled) / 1_000_000_000.0
}

/// Whether `accumulated` voting weight reaches `threshold` of `total`. A zero
/// total never reaches quorum (callers fall back to collecting every result).
#[must_use]
pub fn meets_quorum(accumulated: &BigInt, total: &BigInt, threshold: f64) -> bool {
	bigint_ratio(accumulated, total) >= threshold
}

/// A representative's share of total voting weight. When `total` is zero the
/// share is split evenly across `count` representatives (`0.0` when none).
#[must_use]
pub fn weight_fraction(weight: &BigInt, total: &BigInt, count: usize) -> f64 {
	if total == &BigInt::from(0u8) {
		if count == 0 {
			return 0.0;
		}

		return 1.0 / count as f64;
	}

	bigint_ratio(weight, total)
}

/// The Power-of-Two-Choices effective score: weight fraction scaled by
/// reliability.
#[must_use]
pub fn selection_score(weight_fraction: f64, reliability: f64) -> f64 {
	weight_fraction * reliability
}

/// The hash observed on the most representatives. Ties break to the
/// lexicographically smallest hash for determinism. `None` for no
/// observations.
#[must_use]
pub fn most_common_hash(hashes: &[String]) -> Option<String> {
	let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
	for hash in hashes {
		*counts.entry(hash.as_str()).or_insert(0) += 1;
	}

	counts
		.into_iter()
		.max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(left.0)))
		.map(|(hash, _)| hash.to_string())
}

/// The latest `from` shared by all `(from, to)` validity windows, when their
/// intersection is non-empty. `None` for an empty input or disjoint windows.
#[must_use]
pub fn overlapping_moment(windows: impl IntoIterator<Item = (i64, i64)>) -> Option<i64> {
	let mut latest_from: Option<i64> = None;
	let mut earliest_to: Option<i64> = None;
	for (from, to) in windows {
		latest_from = Some(latest_from.map_or(from, |seen: i64| seen.max(from)));
		earliest_to = Some(earliest_to.map_or(to, |seen: i64| seen.min(to)));
	}

	match (latest_from, earliest_to) {
		(Some(from), Some(to)) if from <= to => Some(from),
		_ => None,
	}
}

/// Double the backoff `delay`, capped at `max` (saturating to avoid overflow).
#[must_use]
pub fn next_backoff(delay: u64, max: u64) -> u64 {
	delay.saturating_mul(2).min(max)
}

fn bigint_to_f64(value: &BigInt) -> f64 {
	value.to_string().parse::<f64>().unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
	use alloc::vec;

	use super::*;

	#[test]
	fn success_adds_then_clamps_to_one() {
		assert!((reliability_after_success(0.5, 0.1) - 0.6).abs() < 1e-9);
		assert_eq!(reliability_after_success(0.95, 1.0), 1.0);
	}

	#[test]
	fn failure_multiplies_then_respects_floor() {
		assert!((reliability_after_failure(1.0, 0.5, 0.01) - 0.5).abs() < 1e-9);
		assert_eq!(reliability_after_failure(0.5, 0.5, 0.4), 0.4);
	}

	#[test]
	fn quorum_reached_at_or_above_threshold() {
		assert!(meets_quorum(&BigInt::from(7), &BigInt::from(10), 0.7));
		assert!(!meets_quorum(&BigInt::from(6), &BigInt::from(10), 0.7));
	}

	#[test]
	fn quorum_never_reached_with_zero_total() {
		assert!(!meets_quorum(&BigInt::from(5), &BigInt::from(0), 0.7));
	}

	#[test]
	fn weight_fraction_splits_evenly_when_total_is_zero() {
		assert!((weight_fraction(&BigInt::from(1), &BigInt::from(0), 4) - 0.25).abs() < 1e-9);
		assert_eq!(weight_fraction(&BigInt::from(1), &BigInt::from(0), 0), 0.0);
	}

	#[test]
	fn weight_fraction_is_the_ratio_when_total_is_nonzero() {
		assert!((weight_fraction(&BigInt::from(3), &BigInt::from(4), 2) - 0.75).abs() < 1e-9);
	}

	#[test]
	fn selection_score_scales_weight_by_reliability() {
		assert!((selection_score(0.5, 0.4) - 0.2).abs() < 1e-9);
	}

	#[test]
	fn most_common_hash_picks_the_majority() {
		let hashes = vec!["a".to_string(), "b".to_string(), "a".to_string()];
		assert_eq!(most_common_hash(&hashes).as_deref(), Some("a"));
	}

	#[test]
	fn most_common_hash_breaks_ties_lexicographically() {
		let hashes = vec!["b".to_string(), "a".to_string()];
		assert_eq!(most_common_hash(&hashes).as_deref(), Some("a"));
	}

	#[test]
	fn most_common_hash_is_none_without_observations() {
		assert_eq!(most_common_hash(&[]), None);
	}

	#[test]
	fn overlapping_moment_picks_latest_from() {
		assert_eq!(overlapping_moment([(0, 100), (50, 200), (30, 80)]), Some(50));
	}

	#[test]
	fn overlapping_moment_is_none_when_disjoint() {
		assert_eq!(overlapping_moment([(0, 40), (50, 100)]), None);
	}

	#[test]
	fn overlapping_moment_is_none_when_empty() {
		assert_eq!(overlapping_moment(core::iter::empty::<(i64, i64)>()), None);
	}

	#[test]
	fn backoff_doubles_until_capped() {
		assert_eq!(next_backoff(1, 500), 2);
		assert_eq!(next_backoff(2, 500), 4);
		assert_eq!(next_backoff(256, 500), 500);
	}

	#[test]
	fn backoff_saturates_without_overflow() {
		assert_eq!(next_backoff(u64::MAX, 500), 500);
	}
}
