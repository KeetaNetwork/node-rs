//! Representative set: voting weights plus the reliability scoring and
//! selection used by the durable dispatch layer.

#![cfg_attr(not(feature = "std"), allow(dead_code))]

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use num_bigint::BigInt;

use crate::math::{reliability_after_failure, reliability_after_success, selection_score, weight_fraction};
use crate::sync::RwLock;

/// One representative's scoring record: a stable key, its advertised API URL,
/// voting weight, and current reliability score.
#[derive(Clone, Debug)]
pub(crate) struct RepRecord {
	/// Stable key (account public-key string, or base URL for an anonymous
	/// single-rep client) used for scoring and weight refresh.
	pub(crate) key: String,
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

/// Construction parts for one representative, consumed by
/// [`KeetaClient::with_parts`](crate::KeetaClient::with_parts).
#[derive(Clone, Debug)]
pub struct RepPart {
	/// Stable scoring key: the representative's account string, or its API
	/// URL for an anonymous single-rep client.
	pub key: String,
	/// API base URL the representative is reached at.
	pub url: String,
	/// Voting weight.
	pub weight: BigInt,
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

	/// The first representative's API URL, if any.
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

	/// Select the representative with the highest effective score.
	fn pick(&self) -> Option<RepRef> {
		let total = self.total_weight();
		let leader = self
			.reps
			.iter()
			.fold(None::<(&RepRecord, f64)>, |best, rep| {
				let score = self.effective_score(rep, &total);
				match best {
					Some((_, top)) if top >= score => best,
					_ => Some((rep, score)),
				}
			});

		leader.map(|(chosen, _)| RepRef { key: chosen.key.clone(), weight: chosen.weight.clone() })
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

	pub(crate) fn pick(&self) -> Option<RepRef> {
		self.state.read().pick()
	}

	pub(crate) fn update_weights(&self, fetched: &[(String, BigInt)]) {
		self.state.write().update_weights(fetched);
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
		let pick = state.pick();
		assert!(matches!(pick, Some(chosen) if chosen.key == "solo"));
	}

	#[test]
	fn pick_on_empty_state_is_none() {
		let state = RepState::new(Vec::new());
		assert!(state.pick().is_none());
	}

	#[test]
	fn pick_always_returns_the_highest_weight_rep() {
		let state = RepState::new(vec![record("light", 1), record("heavy", 99)]);

		let heavy_picks = (0..100)
			.filter(|_| matches!(state.pick(), Some(chosen) if chosen.key == "heavy"))
			.count();

		assert_eq!(heavy_picks, 100);
	}

	#[test]
	fn pick_fails_over_when_the_leader_reliability_decays() {
		let mut state = RepState::new(vec![record("heavy", 99), record("light", 1)]);

		// 0.99 weight * 0.01 reliability < 0.01 weight * 1.0 reliability.
		state.decay("heavy", 0.01, 0.001);

		assert!(matches!(state.pick(), Some(chosen) if chosen.key == "light"));
	}

	#[test]
	fn pick_restores_the_leader_once_its_reliability_recovers() {
		let mut state = RepState::new(vec![record("heavy", 99), record("light", 1)]);
		state.decay("heavy", 0.01, 0.001);

		state.boost("heavy", 1.0);

		assert!(matches!(state.pick(), Some(chosen) if chosen.key == "heavy"));
	}

	#[test]
	fn pick_keeps_the_earlier_rep_on_a_score_tie() {
		let state = RepState::new(vec![record("first", 5), record("second", 5)]);
		assert!(matches!(state.pick(), Some(chosen) if chosen.key == "first"));
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
