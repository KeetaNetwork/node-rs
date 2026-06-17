//! Decode-and-verify abstraction for byte-canonical transport artifacts.
//!
//! Types whose canonical form is a self-contained byte string (signed
//! blocks, vote certificates, vote staples) implement [`Verifiable`] to
//! offer a single decode entry point. The associated [`Verifiable::Context`]
//! carries any extra inputs verification needs (e.g. a validation
//! configuration and a moment for time-bounded checks); types whose
//! verification needs nothing use `Context = ()`.

use alloc::vec::Vec;

/// Reconstruct `Self` from its canonical transport bytes, verifying any
/// invariants required to trust the result.
pub trait Verifiable: Sized {
	/// Extra inputs required to verify this artifact; `()` when none.
	type Context;

	/// Error returned when decoding or verification fails.
	type Error;

	/// Decode `bytes` and verify the artifact under `context`.
	fn verify(bytes: impl Into<Vec<u8>>, context: Self::Context) -> Result<Self, Self::Error>;
}
