//! Conditional `Send`/`Sync` bounds for the client's async traits.
//!
//! Some native targets require `Send + Sync` so a multi-threaded
//! executor (e.g. `tokio`) can drive them. On wasm, futures are
//! single-threaded and browser values are `!Send`, so the bounds relax to
//! nothing, letting a fetch-based backend implement the same traits.

#[cfg(not(target_family = "wasm"))]
mod imp {
	/// Requires [`Send`] on native targets.
	pub trait MaybeSend: Send {}
	impl<T: Send + ?Sized> MaybeSend for T {}

	/// Requires [`Sync`] on native targets.
	pub trait MaybeSync: Sync {}
	impl<T: Sync + ?Sized> MaybeSync for T {}
}

#[cfg(target_family = "wasm")]
mod imp {
	/// Unbounded on wasm targets, where futures are `!Send`.
	pub trait MaybeSend {}
	impl<T: ?Sized> MaybeSend for T {}

	/// Unbounded on wasm targets.
	pub trait MaybeSync {}
	impl<T: ?Sized> MaybeSync for T {}
}

pub use imp::{MaybeSend, MaybeSync};
