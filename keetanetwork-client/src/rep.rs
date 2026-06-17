//! Representative set: per-rep transports, voting weights, and the
//! reliability scoring + selection used by the durable dispatch layer.

use std::collections::HashMap;

use keetanetwork_block::AccountRef;
use num_bigint::BigInt;
use rand::Rng;

use crate::generated::Client as Transport;

/// A representative the client can talk to: its API endpoint, account, and
/// voting weight.
#[derive(Debug, Clone)]
pub struct RepEndpoint {
	api_url: String,
	account: AccountRef,
	weight: BigInt,
}

impl RepEndpoint {
	/// Describe a representative by its API URL, account, and voting weight.
	pub fn new(api_url: impl Into<String>, account: AccountRef, weight: impl Into<BigInt>) -> Self {
		Self { api_url: api_url.into(), account, weight: weight.into() }
	}

	/// The representative's API base URL.
	pub fn api_url(&self) -> &str {
		&self.api_url
	}

	/// The representative's account.
	pub fn account(&self) -> &AccountRef {
		&self.account
	}

	/// The representative's voting weight.
	pub fn weight(&self) -> &BigInt {
		&self.weight
	}
}

/// One representative's live transport, keyed for reliability scoring.
#[derive(Debug)]
pub(crate) struct RepHandle {
	/// Stable key (account public-key string, or base URL for an anonymous
	/// single-rep client) used for scoring and weight refresh.
	pub(crate) key: String,
	pub(crate) weight: BigInt,
	pub(crate) transport: Transport,
}

/// A cloned selection target handed to a dispatched call.
#[derive(Debug, Clone)]
pub(crate) struct RepPick {
	pub(crate) key: String,
	pub(crate) weight: BigInt,
	pub(crate) transport: Transport,
}

/// The mutable representative set plus per-rep reliability scores.
///
/// Held behind a lock by the client. Selection reads scores; success/failure
/// feedback mutates them via AIMD.
#[derive(Debug)]
pub(crate) struct RepState {
	reps: Vec<RepHandle>,
	scores: HashMap<String, f64>,
}

impl RepState {
	pub(crate) fn new(reps: Vec<RepHandle>) -> Self {
		Self { reps, scores: HashMap::new() }
	}

	fn reliability(&self, key: &str) -> f64 {
		self.scores.get(key).copied().unwrap_or(1.0)
	}

	/// Increase a representative's reliability (AIMD additive increase),
	/// clamped to `1.0`.
	pub(crate) fn boost(&mut self, key: &str, increment: f64) {
		let next = crate::math::reliability_after_success(self.reliability(key), increment);
		self.scores.insert(key.to_owned(), next);
	}

	/// Decrease a representative's reliability (AIMD multiplicative
	/// decrease), floored to prevent an absorbing state.
	pub(crate) fn decay(&mut self, key: &str, decay: f64, floor: f64) {
		let next = crate::math::reliability_after_failure(self.reliability(key), decay, floor);
		self.scores.insert(key.to_owned(), next);
	}

	/// The first representative's transport, if any (escape hatch).
	pub(crate) fn first_transport(&self) -> Option<Transport> {
		self.reps.first().map(|rep| rep.transport.clone())
	}

	/// Whether a representative with `key` is already in the set.
	pub(crate) fn contains(&self, key: &str) -> bool {
		self.reps.iter().any(|rep| rep.key == key)
	}

	/// Add a newly discovered representative to the set.
	pub(crate) fn add_rep(&mut self, rep: RepHandle) {
		self.reps.push(rep);
	}

	/// Sorted representative keys, used to namespace the process-shared
	/// representative cache so distinct rep sets never share entries.
	pub(crate) fn sorted_keys(&self) -> Vec<String> {
		let mut keys: Vec<String> = self.reps.iter().map(|rep| rep.key.clone()).collect();
		keys.sort();
		keys
	}

	/// Clone every representative as a fan-out target.
	pub(crate) fn snapshot(&self) -> Vec<RepPick> {
		self.reps
			.iter()
			.map(|rep| RepPick { key: rep.key.clone(), weight: rep.weight.clone(), transport: rep.transport.clone() })
			.collect()
	}

	/// Total voting weight across all representatives.
	pub(crate) fn total_weight(&self) -> BigInt {
		self.reps.iter().map(|rep| rep.weight.clone()).sum()
	}

	/// Select one representative using Power of Two Choices: pick two random
	/// indices and return the one with the higher effective score
	/// (`weight_fraction * reliability`). Equal indices return that rep
	/// directly, guaranteeing every rep a `1/n` baseline.
	pub(crate) fn pick(&self) -> Option<RepPick> {
		let count = self.reps.len();
		if count == 0 {
			return None;
		}

		let chosen = if count == 1 {
			&self.reps[0]
		} else {
			let mut rng = rand::thread_rng();
			let index_a = rng.gen_range(0..count);
			let index_b = rng.gen_range(0..count);
			if self.effective_score(&self.reps[index_a]) >= self.effective_score(&self.reps[index_b]) {
				&self.reps[index_a]
			} else {
				&self.reps[index_b]
			}
		};

		Some(RepPick { key: chosen.key.clone(), weight: chosen.weight.clone(), transport: chosen.transport.clone() })
	}

	fn effective_score(&self, rep: &RepHandle) -> f64 {
		let total = self.total_weight();
		let weight_fraction = crate::math::weight_fraction(&rep.weight, &total, self.reps.len());
		crate::math::selection_score(weight_fraction, self.reliability(&rep.key))
	}

	/// Refresh known representatives' weights from a fetched `(key, weight)`
	/// set, matching by key.
	pub(crate) fn update_weights(&mut self, fetched: &[(String, BigInt)]) {
		for rep in &mut self.reps {
			if let Some((_, weight)) = fetched.iter().find(|(key, _)| key == &rep.key) {
				rep.weight = weight.clone();
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn handle(key: &str, weight: i64) -> RepHandle {
		RepHandle { key: key.to_owned(), weight: BigInt::from(weight), transport: Transport::new("http://localhost") }
	}

	#[test]
	fn boost_increases_reliability_then_clamps_to_one() {
		let mut state = RepState::new(vec![handle("a", 1)]);
		state.decay("a", 0.5, 0.01);
		state.boost("a", 0.1);
		assert!((state.reliability("a") - 0.6).abs() < 1e-9);

		state.boost("a", 1.0);
		assert_eq!(state.reliability("a"), 1.0);
	}

	#[test]
	fn decay_multiplies_and_respects_floor() {
		let mut state = RepState::new(vec![handle("a", 1)]);
		state.decay("a", 0.5, 0.4);
		assert!((state.reliability("a") - 0.5).abs() < 1e-9);

		state.decay("a", 0.5, 0.4);
		assert_eq!(state.reliability("a"), 0.4);
	}

	#[test]
	fn update_weights_matches_by_key_and_ignores_unknown() {
		let mut state = RepState::new(vec![handle("a", 1), handle("b", 2)]);
		state.update_weights(&[("a".to_owned(), BigInt::from(5)), ("c".to_owned(), BigInt::from(9))]);
		assert_eq!(state.total_weight(), BigInt::from(7));
	}

	#[test]
	fn pick_returns_the_only_rep() {
		let state = RepState::new(vec![handle("solo", 1)]);
		let pick = state.pick();
		assert!(matches!(pick, Some(chosen) if chosen.key == "solo"));
	}

	#[test]
	fn pick_on_empty_state_is_none() {
		let state = RepState::new(Vec::new());
		assert!(state.pick().is_none());
	}

	#[test]
	fn sorted_keys_are_namespaced_deterministically() {
		let state = RepState::new(vec![handle("b", 1), handle("a", 1)]);
		assert_eq!(state.sorted_keys(), vec!["a".to_owned(), "b".to_owned()]);
	}

	#[test]
	fn contains_detects_membership_by_key() {
		let state = RepState::new(vec![handle("a", 1)]);
		assert!(state.contains("a"));
		assert!(!state.contains("b"));
	}

	#[test]
	fn add_rep_grows_the_set_and_its_weight() {
		let mut state = RepState::new(vec![handle("a", 1)]);
		state.add_rep(handle("b", 4));
		assert!(state.contains("b"));
		assert_eq!(state.total_weight(), BigInt::from(5));
	}
}
