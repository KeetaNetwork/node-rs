//! Tunable durability parameters for [`KeetaClient`](crate::KeetaClient).

/// Configuration controlling retry, backoff, timeout, representative
/// refresh, reliability scoring, and quorum behavior.
///
/// Construct with [`ClientConfig::default`] and override individual fields,
/// or use the `with_*` builders.
#[derive(Debug, Clone)]
pub struct ClientConfig {
	/// Maximum number of retry attempts for a dispatched call.
	pub max_retries: u32,
	/// Upper bound for the exponential backoff delay, in milliseconds.
	pub max_backoff_ms: u64,
	/// Per-request timeout in milliseconds; `0` disables the timeout.
	pub request_timeout_ms: u64,
	/// Interval between periodic representative-weight refreshes, in
	/// milliseconds.
	pub update_reps_interval_ms: u64,
	/// Time-to-live for the process-shared representative cache, in
	/// milliseconds.
	pub reps_cache_ttl_ms: u64,
	/// Multiplier applied to a representative's reliability on failure
	/// (`0.0..=1.0`).
	pub reliability_decay: f64,
	/// Additive increase applied to reliability on success (clamped to
	/// `1.0`).
	pub reliability_increment: f64,
	/// Minimum reliability a representative can decay to, preventing an
	/// absorbing state.
	pub reliability_floor: f64,
	/// Fraction of total voting weight required for quorum (`0.0..=1.0`).
	pub quorum_threshold: f64,
	/// Whether the periodic refresh also discovers and adds newly advertised
	/// representatives (matching the reference's `addNewReps`).
	pub discover_reps: bool,
}

impl Default for ClientConfig {
	fn default() -> Self {
		Self {
			max_retries: 32,
			max_backoff_ms: 500,
			request_timeout_ms: 0,
			update_reps_interval_ms: 5 * 60 * 1000,
			reps_cache_ttl_ms: 60 * 1000,
			reliability_decay: 0.5,
			reliability_increment: 0.1,
			reliability_floor: 0.01,
			quorum_threshold: 0.7,
			discover_reps: false,
		}
	}
}

impl ClientConfig {
	/// Override [`max_retries`](Self::max_retries).
	#[must_use]
	pub fn with_max_retries(mut self, max_retries: u32) -> Self {
		self.max_retries = max_retries;
		self
	}

	/// Override [`max_backoff_ms`](Self::max_backoff_ms).
	#[must_use]
	pub fn with_max_backoff_ms(mut self, max_backoff_ms: u64) -> Self {
		self.max_backoff_ms = max_backoff_ms;
		self
	}

	/// Override [`request_timeout_ms`](Self::request_timeout_ms).
	#[must_use]
	pub fn with_request_timeout_ms(mut self, request_timeout_ms: u64) -> Self {
		self.request_timeout_ms = request_timeout_ms;
		self
	}

	/// Override [`quorum_threshold`](Self::quorum_threshold).
	#[must_use]
	pub fn with_quorum_threshold(mut self, quorum_threshold: f64) -> Self {
		self.quorum_threshold = quorum_threshold;
		self
	}

	/// Override [`discover_reps`](Self::discover_reps).
	#[must_use]
	pub fn with_discover_reps(mut self, discover_reps: bool) -> Self {
		self.discover_reps = discover_reps;
		self
	}
}
