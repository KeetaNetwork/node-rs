//! Deterministic issuer / validity factories shared by every test in the
//! vote crate (unit + integration).
//!
//! Gated behind the `testing` feature; the crate's own unit tests
//! enable it implicitly via `cfg(test)`. Integration tests opt in through
//! `[[test]] required-features = ["testing"]` in `Cargo.toml`.

use std::sync::Arc;

use keetanetwork_account::doc_utils::{
	create_ed25519_test_keys, create_secp256k1_test_keys, create_secp256r1_test_keys,
};
use keetanetwork_account::GenericAccount;
use keetanetwork_block::testing::padded_seed;
use keetanetwork_block::{AccountRef, BlockTime};

use crate::error::VoteError;
use crate::validity::Validity;

/// A deterministic ed25519 issuer derived from `seed` (any length up to
/// the 64-byte buffer the reference helpers expect).
pub fn ed25519_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_ed25519_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::Ed25519(account))
}

/// A deterministic secp256k1 issuer derived from `seed`.
pub fn secp256k1_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_secp256k1_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::EcdsaSecp256k1(account))
}

/// A deterministic secp256r1 issuer derived from `seed`.
pub fn secp256r1_issuer(seed: impl AsRef<[u8]>) -> AccountRef {
	let (_, _, account) = create_secp256r1_test_keys(Some(&padded_seed(seed.as_ref())));
	Arc::new(GenericAccount::EcdsaSecp256r1(account))
}

/// A [`BlockTime`] from unix milliseconds; panics on the (test-only)
/// out-of-range case.
pub fn moment(ms: i64) -> BlockTime {
	BlockTime::from_unix_millis(ms).expect("test moment must be representable")
}

/// A [`Validity`] from unix-second offsets.
pub fn validity_seconds(from_secs: i64, to_secs: i64) -> Validity {
	validity_millis(from_secs * 1_000, to_secs * 1_000)
}

/// A [`Validity`] from unix-millisecond offsets.
pub fn validity_millis(from_ms: i64, to_ms: i64) -> Validity {
	Validity::try_new(moment(from_ms), moment(to_ms)).expect("validity range must be well-formed")
}

/// A validity range anchored at the current wall clock - 60s of slack
/// before now, 24h after - sized so live-node tests stay valid even on
/// slow runners.
pub fn future_validity() -> Validity {
	let now_ms = chrono::Utc::now().timestamp_millis();
	validity_millis(now_ms - 60_000, now_ms + 24 * 60 * 60 * 1_000)
}

/// Locate the first occurrence of the X.509 `[0] EXPLICIT INTEGER` version
/// tag (`A0 03 02 01 ..`) inside a wire buffer. Used by tests that corrupt
/// the version byte to force a decode failure.
pub fn find_version_tag(buf: &[u8]) -> Result<usize, VoteError> {
	buf.iter()
		.zip(buf.iter().skip(1))
		.position(|(a, b)| *a == 0xa0 && *b == 0x03)
		.ok_or(VoteError::MalformedVoteContent)
}
