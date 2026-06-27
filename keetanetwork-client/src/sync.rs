//! Lock primitives shared by the client, selected for `no_std` support.
//!
//! [`spin`] mutex/rw-lock work in both `std` and `no_std` builds (atomic
//! spin locks, no OS dependency), so the same scoring core compiles under
//! `--no-default-features`.

pub(crate) use spin::{Mutex, Once, RwLock};
