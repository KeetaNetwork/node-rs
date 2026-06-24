//! Diagnostics setup for the node executable.
//!
//! Libraries across the workspace emit [`tracing`] events; the node installs a
//! single global subscriber here. Filtering is driven by the `RUST_LOG`
//! environment variable (see [`tracing_subscriber::EnvFilter`]); when it is
//! unset, the level in [`DEFAULT_FILTER`] applies.
//!
//! The output format is chosen by [`FORMAT_ENV`]:
//!
//! - `pretty` (the default) -- human-readable, colored when stdout is a
//!   terminal. Intended for local development.
//! - `json` -- Google Cloud Operations structured JSON via
//!   [`tracing_stackdriver`], which maps the [`tracing`] level to a GCP
//!   `severity` and lifts the event into a top-level `message`. Intended for
//!   deployed environments that ship stdout to Cloud Logging.

use std::io::{stdout, IsTerminal};

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// The filter applied when `RUST_LOG` is unset.
const DEFAULT_FILTER: &str = "info";

/// The environment variable selecting the output format.
const FORMAT_ENV: &str = "KEETANET_LOG_FORMAT";

/// The `KEETANET_LOG_FORMAT` value selecting structured GCP output.
const JSON_FORMAT: &str = "json";

/// Install the global tracing subscriber. Subsequent calls are ignored, so this
/// is safe to call from `main` and from individual integration tests.
pub fn init() {
	match wants_json() {
		true => init_json(),
		false => init_pretty(),
	}
}

/// Whether the `KEETANET_LOG_FORMAT` environment variable requests JSON output.
fn wants_json() -> bool {
	std::env::var(FORMAT_ENV).is_ok_and(|value| value.eq_ignore_ascii_case(JSON_FORMAT))
}

/// The level filter from `RUST_LOG`, or [`DEFAULT_FILTER`] when it is unset.
fn filter() -> EnvFilter {
	EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
}

/// Human-readable output, colored only when stdout is an interactive terminal.
fn init_pretty() {
	let _ = tracing_subscriber::fmt()
		.with_env_filter(filter())
		.with_ansi(stdout().is_terminal())
		.try_init();
}

/// Google Cloud Operations structured JSON output.
fn init_json() {
	let _ = tracing_subscriber::registry()
		.with(filter())
		.with(tracing_stackdriver::layer())
		.try_init();
}
