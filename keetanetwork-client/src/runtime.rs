//! Runtime: timer, task spawning, and clock abstracted behind [`Runtime`] so
//! the orchestrator never names a concrete executor.
//!
//! The trait is `no_std`+`alloc`; [`TokioRuntime`] is the std backend. Swapping
//! in a different runtime (e.g. an embedded executor), it is the interface that
//! keeps backoff, per-request deadlines, the background refresh task, and cache
//! TTLs executor-agnostic.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

use async_trait::async_trait;

/// A boxed, detached future a [`Runtime`] can drive in the background.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Handle to a spawned background task. Dropping or calling [`abort`] stops it.
///
/// [`abort`]: TaskHandle::abort
pub trait TaskHandle: core::fmt::Debug + Send + Sync {
	/// Stop the spawned task.
	fn abort(&self);
}

/// Asynchronous runtime services the durable dispatch layer needs: sleeping
/// (backoff and the timeout building block), spawning the refresh task, and a
/// monotonic clock for cache freshness.
#[async_trait]
pub trait Runtime: core::fmt::Debug + Send + Sync {
	/// Sleep for `duration`.
	async fn sleep(&self, duration: Duration);
	/// Spawn a detached background task.
	fn spawn(&self, future: BoxFuture) -> Box<dyn TaskHandle>;
	/// Monotonic milliseconds from an arbitrary, runtime-fixed origin, used for
	/// cache-freshness deltas.
	fn now_millis(&self) -> u64;
	/// Wall-clock milliseconds since the Unix epoch, used to stamp the moment
	/// of originated blocks and reconstructed staples. A `no_std` runtime
	/// supplies this from its real-time clock; there is no `core` wall clock.
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
