//! Loaded code, kept within a byte budget.
//!
//! Only a speed-up: code that is not here is reloaded from the host (and
//! its hash checked), so dropping an entry never changes a call's outcome.
//! Entries are keyed by the hash of their code, so they never go stale.

use std::collections::HashMap;

use crate::host::CodeHash;

struct Entry<T> {
	value: T,
	size: usize,
	/// When the entry was last inserted or read: a tick of [`CodeCache::clock`]
	used: u64,
}

/// Values by code hash, holding at most `limit` bytes of code. When an
/// insert goes over, the least recently used entries are dropped.
pub(crate) struct CodeCache<T> {
	entries: HashMap<CodeHash, Entry<T>>,
	limit: usize,
	/// Total `size` of the entries
	bytes: usize,
	clock: u64,
}

impl<T: Clone> CodeCache<T> {
	pub(crate) fn new(limit: usize) -> Self {
		Self { entries: HashMap::new(), limit, bytes: 0, clock: 0 }
	}

	fn tick(&mut self) -> u64 {
		self.clock += 1;
		self.clock
	}

	pub(crate) fn get(&mut self, hash: &CodeHash) -> Option<T> {
		let now = self.tick();
		let entry = self.entries.get_mut(hash)?;
		entry.used = now;
		Some(entry.value.clone())
	}

	/// Keep `value`, counted as `size` bytes. Code larger than the whole
	/// budget is not kept.
	pub(crate) fn insert(&mut self, hash: CodeHash, value: T, size: usize) {
		if size > self.limit {
			return;
		}
		let used = self.tick();
		if let Some(old) = self.entries.insert(hash, Entry { value, size, used }) {
			self.bytes -= old.size;
		}
		self.bytes += size;
		// Linear in the number of entries, but only on an insert that goes
		// over budget: a miss, which also loads and verifies an ELF.
		while self.bytes > self.limit {
			let oldest = self
				.entries
				.iter()
				.filter(|(key, _)| **key != hash)
				.min_by_key(|(_, entry)| entry.used)
				.map(|(key, _)| *key);
			let Some(oldest) = oldest else {
				break;
			};
			if let Some(entry) = self.entries.remove(&oldest) {
				self.bytes -= entry.size;
			}
		}
	}

	#[cfg(test)]
	fn contains(&self, hash: &CodeHash) -> bool {
		self.entries.contains_key(hash)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hash(n: u8) -> CodeHash {
		[n; 32]
	}

	#[test]
	fn drops_the_least_recently_used_code_when_over_budget() {
		let mut cache = CodeCache::new(30);
		cache.insert(hash(1), 1, 10);
		cache.insert(hash(2), 2, 10);
		cache.insert(hash(3), 3, 10);
		// Reading 1 makes 2 the oldest.
		assert_eq!(cache.get(&hash(1)), Some(1));
		cache.insert(hash(4), 4, 10);
		assert!(!cache.contains(&hash(2)));
		assert!(cache.contains(&hash(1)) && cache.contains(&hash(3)) && cache.contains(&hash(4)));
		assert_eq!(cache.bytes, 30);
	}

	#[test]
	fn drops_as_many_entries_as_a_large_insert_needs() {
		let mut cache = CodeCache::new(30);
		cache.insert(hash(1), 1, 10);
		cache.insert(hash(2), 2, 10);
		cache.insert(hash(3), 3, 25);
		assert!(!cache.contains(&hash(1)) && !cache.contains(&hash(2)));
		assert_eq!(cache.get(&hash(3)), Some(3));
		assert_eq!(cache.bytes, 25);
	}

	#[test]
	fn does_not_keep_code_larger_than_the_budget() {
		let mut cache = CodeCache::new(30);
		cache.insert(hash(1), 1, 10);
		cache.insert(hash(2), 2, 31);
		assert_eq!(cache.get(&hash(2)), None);
		assert_eq!(cache.get(&hash(1)), Some(1));
		assert_eq!(cache.bytes, 10);
	}

	#[test]
	fn reinserting_the_same_code_counts_it_once() {
		let mut cache = CodeCache::new(30);
		cache.insert(hash(1), 1, 10);
		cache.insert(hash(1), 1, 10);
		assert_eq!(cache.bytes, 10);
	}

	#[test]
	fn a_zero_budget_keeps_nothing() {
		let mut cache = CodeCache::new(0);
		cache.insert(hash(1), 1, 1);
		assert_eq!(cache.get(&hash(1)), None);
	}
}
