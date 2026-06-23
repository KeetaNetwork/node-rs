//! WASI bindings for the KeetaNet client: two feature-selected flavors over one
//! shared pure-logic core ([`pure`]).
//!
//! - **`p2`** ([`wasm32-wasip2`]): a `wit-bindgen` component, networked over
//!   `wasi:http` plus the pure surface.
//! - **`p1`** ([`wasm32-wasip1`]): a core module, pure/offline only over a flat
//!   ABI (P1 has no outbound `connect`, so the host dials).
//!
//! Exactly one of `p1`/`p2` is enabled per wasi build; off a wasi target both
//! compile out, leaving just [`pure`].
//!
//! [`wasm32-wasip1`]: https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip1.html
//! [`wasm32-wasip2`]: https://doc.rust-lang.org/rustc/platform-support/wasm32-wasip2.html

#[cfg(all(target_os = "wasi", feature = "p1", feature = "p2"))]
compile_error!("enable exactly one of the `p1` or `p2` features for a wasi build");
#[cfg(all(target_os = "wasi", not(any(feature = "p1", feature = "p2"))))]
compile_error!("enable exactly one of the `p1` or `p2` features for a wasi build");

pub mod pure;

#[cfg(all(feature = "p2", target_os = "wasi"))]
mod p2;

#[cfg(all(feature = "p1", target_os = "wasi"))]
mod p1;
