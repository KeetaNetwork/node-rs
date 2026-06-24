//! Key-value store boundary used by the switch for peer registries and
//! seen-message de-duplication.
//!
//! A namespaced map with optional per-entry TTL and an exclusive-create
//! primitive (used to atomically claim a message id the first time it is seen).

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

/// A namespaced, optionally-expiring key-value store.
///
/// Async so a backend can be remote (a database or networked store), not only
/// the in-memory [`MemoryKvStore`].
#[async_trait]
pub trait KvStore: Send + Sync {
	/// The live value at `namespace`/`key`, or `None` when absent or expired.
	async fn get(&self, namespace: &str, key: &str, now_ms: i64) -> Option<Value>;
	/// Every live entry in `namespace`.
	async fn get_all(&self, namespace: &str, now_ms: i64) -> BTreeMap<String, Value>;
	/// Insert or overwrite `namespace`/`key`, optionally expiring after
	/// `ttl_ms` from `now_ms`.
	async fn set(&self, namespace: &str, key: &str, value: Value, ttl_ms: Option<i64>, now_ms: i64);
	/// Insert only if no live entry exists. Returns `true` when the entry was
	/// created, `false` when a live one already occupied the slot.
	async fn set_exclusive(&self, namespace: &str, key: &str, value: Value, ttl_ms: Option<i64>, now_ms: i64) -> bool;
}

/// One stored value and its optional absolute expiry (unix millis).
#[derive(Clone, Debug)]
struct Entry {
	value: Value,
	expires_at: Option<i64>,
}

impl Entry {
	fn is_live(&self, now_ms: i64) -> bool {
		match self.expires_at {
			Some(expiry) => expiry > now_ms,
			None => true,
		}
	}
}

/// In-memory [`KvStore`], suitable for a single-process node or tests.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
	entries: Mutex<BTreeMap<(String, String), Entry>>,
}

impl MemoryKvStore {
	/// An empty store.
	pub fn new() -> Self {
		Self::default()
	}

	fn entry(ttl_ms: Option<i64>, now_ms: i64, value: Value) -> Entry {
		Entry { value, expires_at: ttl_ms.map(|ttl| now_ms.saturating_add(ttl)) }
	}
}

#[async_trait]
impl KvStore for MemoryKvStore {
	async fn get(&self, namespace: &str, key: &str, now_ms: i64) -> Option<Value> {
		let entries = self.entries.lock().ok()?;
		entries
			.get(&(namespace.to_owned(), key.to_owned()))
			.filter(|entry| entry.is_live(now_ms))
			.map(|entry| entry.value.clone())
	}

	async fn get_all(&self, namespace: &str, now_ms: i64) -> BTreeMap<String, Value> {
		let Ok(entries) = self.entries.lock() else {
			return BTreeMap::new();
		};

		entries
			.iter()
			.filter(|((entry_namespace, _), entry)| entry_namespace == namespace && entry.is_live(now_ms))
			.map(|((_, key), entry)| (key.clone(), entry.value.clone()))
			.collect()
	}

	async fn set(&self, namespace: &str, key: &str, value: Value, ttl_ms: Option<i64>, now_ms: i64) {
		let Ok(mut entries) = self.entries.lock() else {
			return;
		};
		entries.insert((namespace.to_owned(), key.to_owned()), Self::entry(ttl_ms, now_ms, value));
	}

	async fn set_exclusive(&self, namespace: &str, key: &str, value: Value, ttl_ms: Option<i64>, now_ms: i64) -> bool {
		let Ok(mut entries) = self.entries.lock() else {
			return false;
		};

		let slot = (namespace.to_owned(), key.to_owned());
		let occupied = entries
			.get(&slot)
			.is_some_and(|entry| entry.is_live(now_ms));
		if occupied {
			return false;
		}

		entries.insert(slot, Self::entry(ttl_ms, now_ms, value));
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn set_then_get_round_trips() {
		let store = MemoryKvStore::new();
		store.set("peers", "a", Value::from("one"), None, 0).await;
		assert_eq!(store.get("peers", "a", 0).await, Some(Value::from("one")), "a live entry must read back");
	}

	#[tokio::test]
	async fn ttl_entry_expires_after_window() {
		let store = MemoryKvStore::new();
		store.set("seen", "id", Value::from(1), Some(100), 0).await;
		assert!(store.get("seen", "id", 50).await.is_some(), "entry must be live before expiry");
		assert!(store.get("seen", "id", 150).await.is_none(), "entry must be gone after expiry");
	}

	#[tokio::test]
	async fn exclusive_create_rejects_a_live_duplicate() {
		let store = MemoryKvStore::new();
		assert!(store.set_exclusive("seen", "id", Value::from(1), Some(100), 0).await, "first claim must succeed");
		assert!(!store.set_exclusive("seen", "id", Value::from(2), Some(100), 0).await, "duplicate claim must fail");
	}

	#[tokio::test]
	async fn exclusive_create_succeeds_after_expiry() {
		let store = MemoryKvStore::new();
		assert!(store.set_exclusive("seen", "id", Value::from(1), Some(100), 0).await, "first claim must succeed");
		assert!(store.set_exclusive("seen", "id", Value::from(2), Some(100), 200).await, "claim after expiry must succeed");
	}

	#[tokio::test]
	async fn get_all_returns_only_the_namespace() {
		let store = MemoryKvStore::new();
		store.set("peers", "a", Value::from(1), None, 0).await;
		store.set("peers", "b", Value::from(2), None, 0).await;
		store.set("other", "c", Value::from(3), None, 0).await;

		let peers = store.get_all("peers", 0).await;
		assert_eq!(peers.len(), 2, "only the queried namespace must be returned");
	}
}
