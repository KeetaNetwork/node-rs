//! Representative set: voting weights plus the reliability scoring and
//! selection used by the durable dispatch layer.

#![cfg_attr(not(feature = "std"), allow(dead_code))]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use num_bigint::BigInt;
use rand_core::RngCore;

use crate::math::{reliability_after_failure, reliability_after_success, selection_score, weight_fraction};
use crate::sync::RwLock;

/// One representative's scoring record: a stable key, its advertised API URL,
/// voting weight, and current reliability score.
#[derive(Clone, Debug)]
pub(crate) struct RepRecord {
	/// Stable key (account public-key string, or base URL for an anonymous
	/// single-rep client) used for scoring and weight refresh.
	pub(crate) key: String,
	/// API base URL, retained for the generated-transport escape hatch.
	pub(crate) url: String,
	pub(crate) weight: BigInt,
	score: f64,
}

impl RepRecord {
	/// A record for a freshly known representative, scored as fully reliable.
	pub(crate) fn new(key: impl Into<String>, url: impl Into<String>, weight: impl Into<BigInt>) -> Self {
		Self { key: key.into(), url: url.into(), weight: weight.into(), score: 1.0 }
	}
}

/// A cloned selection target: the representative's key and weight. The live
/// transport is bound by `key` in the std client.
#[derive(Clone, Debug)]
pub(crate) struct RepRef {
	pub(crate) key: String,
	pub(crate) weight: BigInt,
}

/// The mutable representative set plus per-rep reliability scores.
///
/// Selection reads scores; success/failure feedback mutates them via AIMD.
#[derive(Debug)]
pub(crate) struct RepState {
	reps: Vec<RepRecord>,
}

impl RepState {
	pub(crate) fn new(reps: Vec<RepRecord>) -> Self {
		Self { reps }
	}

	fn reliability(&self, key: &str) -> f64 {
		self.reps
			.iter()
			.find(|rep| rep.key == key)
			.map(|rep| rep.score)
			.unwrap_or(1.0)
	}

	fn set_score(&mut self, key: &str, score: f64) {
		if let Some(rep) = self.reps.iter_mut().find(|rep| rep.key == key) {
			rep.score = score;
		}
	}

	/// Increase a representative's reliability (AIMD additive increase),
	/// clamped to `1.0`.
	fn boost(&mut self, key: &str, increment: f64) {
		let next = reliability_after_success(self.reliability(key), increment);
		self.set_score(key, next);
	}

	/// Decrease a representative's reliability (AIMD multiplicative decrease),
	/// floored to prevent an absorbing state.
	fn decay(&mut self, key: &str, decay: f64, floor: f64) {
		let next = reliability_after_failure(self.reliability(key), decay, floor);
		self.set_score(key, next);
	}

	/// The first representative's API URL, if any (escape hatch for building a
	/// fresh generated transport).
	fn first_url(&self) -> Option<String> {
		self.reps.first().map(|rep| rep.url.clone())
	}

	/// Whether a representative with `key` is already in the set.
	fn contains(&self, key: &str) -> bool {
		self.reps.iter().any(|rep| rep.key == key)
	}

	/// Add a newly discovered representative to the set.
	fn add(&mut self, rep: RepRecord) {
		self.reps.push(rep);
	}

	/// Sorted representative keys, used to namespace the process-shared
	/// representative cache so distinct rep sets never share entries.
	fn sorted_keys(&self) -> Vec<String> {
		let mut keys: Vec<String> = self.reps.iter().map(|rep| rep.key.clone()).collect();
		keys.sort();
		keys
	}

	/// Clone every representative as a fan-out target.
	fn snapshot(&self) -> Vec<RepRef> {
		self.reps
			.iter()
			.map(|rep| RepRef { key: rep.key.clone(), weight: rep.weight.clone() })
			.collect()
	}

	/// Total voting weight across all representatives.
	fn total_weight(&self) -> BigInt {
		self.reps.iter().map(|rep| rep.weight.clone()).sum()
	}

	/// Select one representative using Power of Two Choices: pick two random
	/// indices and return the one with the higher effective score
	/// (`weight_fraction * reliability`). Equal indices return that rep
	/// directly, guaranteeing every rep a `1/n^2` baseline.
	fn pick(&self, rng: &mut impl RngCore) -> Option<RepRef> {
		let count = self.reps.len();
		if count == 0 {
			return None;
		}

		let chosen = if count == 1 {
			&self.reps[0]
		} else {
			let total = self.total_weight();
			let index_a = (rng.next_u32() as usize) % count;
			let index_b = (rng.next_u32() as usize) % count;
			if self.effective_score(&self.reps[index_a], &total) >= self.effective_score(&self.reps[index_b], &total) {
				&self.reps[index_a]
			} else {
				&self.reps[index_b]
			}
		};

		Some(RepRef { key: chosen.key.clone(), weight: chosen.weight.clone() })
	}

	fn effective_score(&self, rep: &RepRecord, total: &BigInt) -> f64 {
		let fraction = weight_fraction(&rep.weight, total, self.reps.len());
		selection_score(fraction, self.reliability(&rep.key))
	}

	/// Refresh known representatives' weights from a fetched `(key, weight)`
	/// set, matching by key.
	fn update_weights(&mut self, fetched: &[(String, BigInt)]) {
		let indexed: BTreeMap<&str, &BigInt> = fetched
			.iter()
			.map(|(key, weight)| (key.as_str(), weight))
			.collect();
		for rep in &mut self.reps {
			if let Some(weight) = indexed.get(rep.key.as_str()) {
				rep.weight = (*weight).clone();
			}
		}
	}
}

/// Interior-mutable representative book: the scoring core behind a spin
/// [`RwLock`], shared by the client's clones. Reads (selection, snapshots)
/// take the read lock; AIMD feedback and discovery take the write lock.
#[derive(Debug)]
pub(crate) struct RepBook {
	state: RwLock<RepState>,
}

impl RepBook {
	pub(crate) fn new(reps: Vec<RepRecord>) -> Self {
		Self { state: RwLock::new(RepState::new(reps)) }
	}

	pub(crate) fn boost(&self, key: &str, increment: f64) {
		self.state.write().boost(key, increment);
	}

	pub(crate) fn decay(&self, key: &str, decay: f64, floor: f64) {
		self.state.write().decay(key, decay, floor);
	}

	pub(crate) fn first_url(&self) -> Option<String> {
		self.state.read().first_url()
	}

	pub(crate) fn contains(&self, key: &str) -> bool {
		self.state.read().contains(key)
	}

	pub(crate) fn add(&self, rep: RepRecord) {
		self.state.write().add(rep);
	}

	pub(crate) fn sorted_keys(&self) -> Vec<String> {
		self.state.read().sorted_keys()
	}

	pub(crate) fn snapshot(&self) -> Vec<RepRef> {
		self.state.read().snapshot()
	}

	/// A snapshot paired with the total weight, taken under one read lock for
	/// the quote fan-out's quorum accounting.
	pub(crate) fn snapshot_with_total(&self) -> (Vec<RepRef>, BigInt) {
		let state = self.state.read();
		(state.snapshot(), state.total_weight())
	}

	pub(crate) fn pick(&self, rng: &mut impl RngCore) -> Option<RepRef> {
		self.state.read().pick(rng)
	}

	pub(crate) fn update_weights(&self, fetched: &[(String, BigInt)]) {
		self.state.write().update_weights(fetched);
	}
}

/// A minimal `no_std` PRNG (`splitmix64`) for Power-of-Two-Choices selection.
///
/// Selection needs only spread, not cryptographic randomness, so a tiny
/// seed-able generator replaces the std `rand` thread RNG and keeps rep
/// selection `no_std`. Seed it per pick from a monotonic clock mixed with a
/// counter so successive picks differ.
pub(crate) struct SmallRng(u64);

impl SmallRng {
	/// A generator seeded from `seed`.
	pub(crate) fn seed_from_u64(seed: u64) -> Self {
		Self(seed)
	}
}

impl RngCore for SmallRng {
	fn next_u64(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
		z ^ (z >> 31)
	}

	fn next_u32(&mut self) -> u32 {
		(self.next_u64() >> 32) as u32
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		let mut chunks = dest.chunks_exact_mut(8);
		for chunk in &mut chunks {
			chunk.copy_from_slice(&self.next_u64().to_le_bytes());
		}
		let remainder = chunks.into_remainder();
		if !remainder.is_empty() {
			let bytes = self.next_u64().to_le_bytes();
			remainder.copy_from_slice(&bytes[..remainder.len()]);
		}
	}
}

/// A representative the client can talk to: its API endpoint, account, and
/// voting weight.
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct RepEndpoint {
	api_url: String,
	account: keetanetwork_block::AccountRef,
	weight: BigInt,
}

#[cfg(feature = "http")]
impl RepEndpoint {
	/// Describe a representative by its API URL, account, and voting weight.
	pub fn new(api_url: impl Into<String>, account: keetanetwork_block::AccountRef, weight: impl Into<BigInt>) -> Self {
		Self { api_url: api_url.into(), account, weight: weight.into() }
	}

	/// The representative's API base URL.
	pub fn api_url(&self) -> &str {
		&self.api_url
	}

	/// The representative's account.
	pub fn account(&self) -> &keetanetwork_block::AccountRef {
		&self.account
	}

	/// The representative's voting weight.
	pub fn weight(&self) -> &BigInt {
		&self.weight
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn record(key: &str, weight: i64) -> RepRecord {
		RepRecord::new(key, "http://localhost", weight)
	}

	#[test]
	fn boost_increases_reliability_then_clamps_to_one() {
		let mut state = RepState::new(vec![record("a", 1)]);
		state.decay("a", 0.5, 0.01);
		state.boost("a", 0.1);
		assert!((state.reliability("a") - 0.6).abs() < 1e-9);

		state.boost("a", 1.0);
		assert_eq!(state.reliability("a"), 1.0);
	}

	#[test]
	fn decay_multiplies_and_respects_floor() {
		let mut state = RepState::new(vec![record("a", 1)]);
		state.decay("a", 0.5, 0.4);
		assert!((state.reliability("a") - 0.5).abs() < 1e-9);

		state.decay("a", 0.5, 0.4);
		assert_eq!(state.reliability("a"), 0.4);
	}

	#[test]
	fn update_weights_matches_by_key_and_ignores_unknown() {
		let mut state = RepState::new(vec![record("a", 1), record("b", 2)]);
		state.update_weights(&[("a".to_owned(), BigInt::from(5)), ("c".to_owned(), BigInt::from(9))]);
		assert_eq!(state.total_weight(), BigInt::from(7));
	}

	#[test]
	fn pick_returns_the_only_rep() {
		let state = RepState::new(vec![record("solo", 1)]);
		let pick = state.pick(&mut SmallRng::seed_from_u64(1));
		assert!(matches!(pick, Some(chosen) if chosen.key == "solo"));
	}

	#[test]
	fn pick_on_empty_state_is_none() {
		let state = RepState::new(Vec::new());
		assert!(state.pick(&mut SmallRng::seed_from_u64(1)).is_none());
	}

	#[test]
	fn sorted_keys_are_namespaced_deterministically() {
		let state = RepState::new(vec![record("b", 1), record("a", 1)]);
		assert_eq!(state.sorted_keys(), vec!["a".to_owned(), "b".to_owned()]);
	}

	#[test]
	fn contains_detects_membership_by_key() {
		let state = RepState::new(vec![record("a", 1)]);
		assert!(state.contains("a"));
		assert!(!state.contains("b"));
	}

	#[test]
	fn add_grows_the_set_and_its_weight() {
		let mut state = RepState::new(vec![record("a", 1)]);
		state.add(record("b", 4));
		assert!(state.contains("b"));
		assert_eq!(state.total_weight(), BigInt::from(5));
	}

	#[test]
	fn book_shares_scores_through_the_lock() {
		let book = RepBook::new(vec![record("a", 1)]);
		book.decay("a", 0.5, 0.01);
		book.boost("a", 0.1);
		let (snapshot, total) = book.snapshot_with_total();
		assert!(snapshot.iter().any(|rep| rep.key == "a"));
		assert_eq!(total, BigInt::from(1));
	}
}
