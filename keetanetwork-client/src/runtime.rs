//! Runtime: timer, task spawning, and clock abstracted behind [`Runtime`] so
//! the orchestrator never names a concrete executor.
//!
//! The trait is `no_std`+`alloc`; [`TokioRuntime`] is the std backend. Routing
//! backoff, per-request deadlines, the background refresh task, and cache TTLs
//! through this interface keeps them executor-agnostic, so a different runtime
//! (e.g. an embedded executor) can be supplied without touching the orchestrator.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use async_trait::async_trait;

use crate::marker::{MaybeSend, MaybeSync};

/// A boxed, detached future a [`Runtime`] can drive in the background. The
/// `Send` bound is required on native targets (multi-threaded executors) and
/// dropped on wasm, where spawned futures are single-threaded.
#[cfg(not(target_family = "wasm"))]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A boxed, detached future a [`Runtime`] can drive in the background.
#[cfg(target_family = "wasm")]
pub type BoxFuture = Pin<Box<dyn Future<Output = ()>>>;

/// Handle to a spawned background task. Dropping or calling [`abort`] stops it.
///
/// [`abort`]: TaskHandle::abort
pub trait TaskHandle: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Stop the spawned task.
	fn abort(&self);
}

/// Asynchronous runtime services the durable dispatch layer needs: sleeping
/// (backoff and the timeout building block), spawning the refresh task, and a
/// monotonic clock for cache freshness.
#[cfg_attr(not(target_family = "wasm"), async_trait)]
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
pub trait Runtime: core::fmt::Debug + MaybeSend + MaybeSync {
	/// Sleep for `duration`.
	async fn sleep(&self, duration: Duration);
	/// Spawn a detached background task.
	fn spawn(&self, future: BoxFuture) -> Box<dyn TaskHandle>;
	/// Monotonic milliseconds from an arbitrary, runtime-fixed origin, used for
	/// cache-freshness deltas.
	fn now_millis(&self) -> u64;
	/// Clock milliseconds since the Unix epoch, used to stamp the moment
	/// of originated blocks and reconstructed staples. A `no_std` runtime
	/// supplies this from its real-time clock; there is no `core` clock.
	fn unix_millis(&self) -> i64;
}

/// Production [`Runtime`] backed by `tokio`.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioRuntime;

/// A tokio task handle that aborts the task on [`abort`](TaskHandle::abort).
#[cfg(feature = "std")]
#[derive(Debug)]
struct TokioTask(tokio::task::JoinHandle<()>);

#[cfg(feature = "std")]
impl TaskHandle for TokioTask {
	fn abort(&self) {
		self.0.abort();
	}
}

#[cfg(feature = "std")]
#[async_trait]
impl Runtime for TokioRuntime {
	async fn sleep(&self, duration: Duration) {
		tokio::time::sleep(duration).await;
	}

	fn spawn(&self, future: BoxFuture) -> Box<dyn TaskHandle> {
		Box::new(TokioTask(tokio::spawn(future)))
	}

	fn now_millis(&self) -> u64 {
		use std::sync::OnceLock;
		use std::time::Instant;

		static ORIGIN: OnceLock<Instant> = OnceLock::new();
		ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
	}

	fn unix_millis(&self) -> i64 {
		use std::time::{SystemTime, UNIX_EPOCH};

		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|elapsed| elapsed.as_millis() as i64)
			.unwrap_or(0)
	}
}

/// Production [`Runtime`] for the browser, backed by `setTimeout` for sleeps
/// and the micro-task queue for spawned tasks.
#[cfg(all(feature = "wasm", target_family = "wasm"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct WasmRuntime;

/// A spawned browser task that stops its future when [`abort`] is called or the
/// handle is dropped, via the [`Abortable`] wrapper applied at spawn time.
///
/// [`abort`]: TaskHandle::abort
/// [`Abortable`]: futures::future::Abortable
#[cfg(all(feature = "wasm", target_family = "wasm"))]
#[derive(Debug)]
struct WasmTask(futures::future::AbortHandle);

#[cfg(all(feature = "wasm", target_family = "wasm"))]
impl TaskHandle for WasmTask {
	fn abort(&self) {
		self.0.abort();
	}
}

#[cfg(all(feature = "wasm", target_family = "wasm"))]
#[async_trait(?Send)]
impl Runtime for WasmRuntime {
	async fn sleep(&self, duration: Duration) {
		let millis = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
		gloo_timers::future::TimeoutFuture::new(millis).await;
	}

	fn spawn(&self, future: BoxFuture) -> Box<dyn TaskHandle> {
		let (handle, registration) = futures::future::AbortHandle::new_pair();
		let task = futures::future::Abortable::new(future, registration);
		wasm_bindgen_futures::spawn_local(async move {
			let _ = task.await;
		});
		Box::new(WasmTask(handle))
	}

	fn now_millis(&self) -> u64 {
		web_sys::window()
			.and_then(|window| window.performance())
			.map(|performance| performance.now())
			.unwrap_or_else(js_sys::Date::now) as u64
	}

	fn unix_millis(&self) -> i64 {
		js_sys::Date::now() as i64
	}
}
