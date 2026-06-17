//! Decode-and-verify abstraction for byte-canonical transport artifacts.

use alloc::vec::Vec;

/// Types that can be decoded from bytes and verified in a single step.
///
/// Implementors decode a byte-canonical transport representation and only
/// return a value once it has been fully verified, so holding `Self` implies
/// the artifact was valid.
pub trait Verifiable: Sized {
	/// Extra context required to verify (e.g. validation config and time).
	type Context;

	/// Error produced when decoding or verification fails.
	type Error;

	/// Decode and verify `bytes`, returning the verified value.
	fn verify(bytes: impl Into<Vec<u8>>, context: Self::Context) -> Result<Self, Self::Error>;
}
