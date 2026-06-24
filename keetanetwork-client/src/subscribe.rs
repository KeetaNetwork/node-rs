//! Account change subscription.
//!
//! A filtered WebSocket listener greets a representative's p2p endpoint,
//! watches for `add` notifications, and emits when the operating account's
//! ledger state changes.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use keetanetwork_block::AccountRef;

use crate::client::KeetaClient;
use crate::marker::{MaybeSend, MaybeSync};
use crate::model::AccountState;
use crate::runtime::{Runtime, TaskHandle};
use crate::sync::Mutex;
use crate::ws::{WsConnector, WsError, WsMessage};

/// Base reconnect delay; doubled per consecutive failure.
const RECONNECT_BASE_MS: u64 = 1_000;
/// Ceiling on the reconnect delay.
const RECONNECT_MAX_MS: u64 = 60_000;
/// Largest left-shift applied to the base delay, capping exponential growth
/// before the [`RECONNECT_MAX_MS`] ceiling clamps it.
const RECONNECT_MAX_SHIFT: u32 = 6;
/// Polling fallback period.
const FALLBACK_POLL_MS: u64 = 60_000;
/// `NodeKind::PARTICIPANT` discriminant.
const PARTICIPANT_KIND: u8 = 0;

/// Events a [`UserClient`](crate::UserClient) subscription can emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UserEvent {
	/// The operating account's ledger state changed.
	Change,
}

/// Handle returned by [`UserClient::on`](crate::UserClient::on), passed back
/// to [`UserClient::off`](crate::UserClient::off) to cancel a listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SubscriptionId(u64);

/// Behavior of a change handler.
pub(crate) trait ChangeFn: Fn(&AccountState) + MaybeSend + MaybeSync {}

impl<T: Fn(&AccountState) + MaybeSend + MaybeSync> ChangeFn for T {}

/// A registered change handler. `Arc` so the listener can snapshot the set and
/// invoke without holding the registry lock.
pub(crate) type ChangeHandler = Arc<dyn ChangeFn>;

/// Shared subscription state behind an [`Arc`], so the background listener and
/// poller observe the same handler registry and last-seen fingerprint.
struct Inner {
	client: KeetaClient,
	runtime: Arc<dyn Runtime>,
	connector: Arc<dyn WsConnector>,
	account: AccountRef,
	p2p_url: String,
	handlers: Mutex<BTreeMap<u64, ChangeHandler>>,
	next_handler_id: AtomicU64,
	message_counter: AtomicU64,
	fingerprint: Mutex<Option<String>>,
	reconnect_attempts: AtomicU32,
	listener: Mutex<Option<Box<dyn TaskHandle>>>,
	poller: Mutex<Option<Box<dyn TaskHandle>>>,
}

/// A change subscription bound to one operating account and connector.
#[derive(Clone)]
pub(crate) struct Subscription(Arc<Inner>);

impl Subscription {
	/// Bind a subscription to `account`, dialing `p2p_url` through `connector`
	/// and driven by the client's shared runtime.
	pub(crate) fn new(
		client: KeetaClient,
		connector: Arc<dyn WsConnector>,
		account: AccountRef,
		p2p_url: String,
	) -> Self {
		let runtime = client.runtime();
		Self(Arc::new(Inner {
			client,
			runtime,
			connector,
			account,
			p2p_url,
			handlers: Mutex::new(BTreeMap::new()),
			next_handler_id: AtomicU64::new(0),
			message_counter: AtomicU64::new(0),
			fingerprint: Mutex::new(None),
			reconnect_attempts: AtomicU32::new(0),
			listener: Mutex::new(None),
			poller: Mutex::new(None),
		}))
	}

	/// Register a change handler, spawning the listener and poller on the
	/// first registration.
	pub(crate) fn register(&self, handler: ChangeHandler) -> SubscriptionId {
		let id = self.0.next_handler_id.fetch_add(1, Ordering::Relaxed);
		let was_empty = {
			let mut handlers = self.0.handlers.lock();
			let empty = handlers.is_empty();
			handlers.insert(id, handler);
			empty
		};

		if was_empty {
			self.spawn_tasks();
		}

		SubscriptionId(id)
	}

	/// Cancel a handler, aborting the background tasks once none remain.
	pub(crate) fn unregister(&self, id: SubscriptionId) {
		let now_empty = {
			let mut handlers = self.0.handlers.lock();
			handlers.remove(&id.0);
			handlers.is_empty()
		};

		if now_empty {
			if let Some(handle) = self.0.listener.lock().take() {
				handle.abort();
			}
			if let Some(handle) = self.0.poller.lock().take() {
				handle.abort();
			}
		}
	}

	fn spawn_tasks(&self) {
		let listener = self.clone();
		let listener_handle = self
			.0
			.runtime
			.spawn(Box::pin(async move { run_listener(listener).await }));

		*self.0.listener.lock() = Some(listener_handle);

		let poller = self.clone();
		let poller_handle = self
			.0
			.runtime
			.spawn(Box::pin(async move { run_poller(poller).await }));

		*self.0.poller.lock() = Some(poller_handle);
	}
}

/// Whether any change handlers remain registered.
fn has_handlers(inner: &Inner) -> bool {
	!inner.handlers.lock().is_empty()
}

/// Reconnecting listener loop: connect, greet, drain notifications, then back
/// off and retry while handlers remain.
async fn run_listener(subscription: Subscription) {
	let inner = subscription.0;
	while has_handlers(&inner) {
		let _ = listen_once(&inner).await;

		if !has_handlers(&inner) {
			return;
		}

		let attempts = inner.reconnect_attempts.fetch_add(1, Ordering::Relaxed);
		let shift = attempts.min(RECONNECT_MAX_SHIFT);
		let backoff_ms = RECONNECT_BASE_MS.saturating_mul(1u64 << shift).min(RECONNECT_MAX_MS);
		inner.runtime.sleep(Duration::from_millis(backoff_ms)).await;
	}
}

/// One connection lifetime: greet the peer, then emit on each `add` until the
/// socket closes or errors.
async fn listen_once(inner: &Inner) -> Result<(), WsError> {
	let connection = inner.connector.connect(&inner.p2p_url).await?;
	connection.send_text(&greeting(inner)).await?;

	loop {
		let Some(message) = connection.recv().await? else {
			return Ok(());
		};

		let text = match message {
			WsMessage::Text(text) => text,
			WsMessage::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
		};

		let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
			continue;
		};

		if value.get("greeting").is_some() {
			inner.reconnect_attempts.store(0, Ordering::Relaxed);
			continue;
		}

		if value.get("add").is_some() {
			emit_if_changed(inner).await;
		}
	}
}

/// The filtered greeting frame announcing this participant and its account
/// filter to the representative.
fn greeting(inner: &Inner) -> String {
	greeting_frame(&next_message_id(inner), &inner.account.to_string())
}

/// Build the participant greeting frame for message `id` filtered to
/// `account`. Pure (no `Inner`) so the encoded shape is unit-testable.
fn greeting_frame(id: &str, account: &str) -> String {
	serde_json::json!({
		"id": id,
		"greeting": {
			"kind": PARTICIPANT_KIND,
			"filter": account,
		}
	})
	.to_string()
}

/// A per-connection-unique message id from the clock and a counter.
fn next_message_id(inner: &Inner) -> String {
	let counter = inner.message_counter.fetch_add(1, Ordering::Relaxed);
	let millis = inner.runtime.unix_millis();
	format!("{millis:x}-{counter:x}")
}

/// Polling fallback: periodically re-check account state in case a socket
/// notification was missed.
async fn run_poller(subscription: Subscription) {
	let inner = subscription.0;
	loop {
		inner.runtime.sleep(Duration::from_millis(FALLBACK_POLL_MS)).await;

		if !has_handlers(&inner) {
			return;
		}

		emit_if_changed(&inner).await;
	}
}

/// Fetch the operating account's state, and if its fingerprint differs from
/// the last seen, invoke every registered handler.
async fn emit_if_changed(inner: &Inner) {
	let Ok(state) = inner.client.state(inner.account.to_string()).await else {
		return;
	};

	let fingerprint = format!("{state:?}");
	let changed = {
		let mut last = inner.fingerprint.lock();
		let differs = last.as_deref() != Some(fingerprint.as_str());
		if differs {
			*last = Some(fingerprint);
		}

		differs
	};

	if !changed {
		return;
	}

	let handlers: Vec<ChangeHandler> = inner.handlers.lock().values().cloned().collect();
	for handler in handlers {
		handler(&state);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn greeting_frame_is_filtered_participant() {
		let frame = greeting_frame("abc-1", "keeta_test_account");
		let value: serde_json::Value = serde_json::from_str(&frame).expect("greeting must be valid json");
		assert_eq!(value["id"], "abc-1");
		assert_eq!(value["greeting"]["kind"], PARTICIPANT_KIND);
		assert_eq!(value["greeting"]["filter"], "keeta_test_account");
	}
}
