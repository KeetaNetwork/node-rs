//! Opaque-handle registry shared by the flat-ABI binding surfaces.
//!
//! A raw FFI surface (e.g. a WASI P1 core module) cannot pass Rust objects
//! across the boundary, so it exposes them as opaque integer handles backed by
//! an internal table.

use alloc::collections::BTreeMap;
use alloc::format;

use crate::error::CodedError;

/// Code for a request referencing an unknown or freed handle.
pub const INVALID_HANDLE: &str = "INVALID_HANDLE";

/// An opaque-handle table for `T`.
pub struct HandleRegistry<T> {
	resource: &'static str,
	next: i32,
	entries: BTreeMap<i32, T>,
}

impl<T> HandleRegistry<T> {
	/// An empty registry whose errors name `resource`.
	pub const fn new(resource: &'static str) -> Self {
		Self { resource, next: 0, entries: BTreeMap::new() }
	}

	/// Store `value` under a fresh non-zero handle and return the handle.
	///
	/// Skips zero and any handle still live, so a wrapped counter never
	/// reassigns an existing entry.
	pub fn store(&mut self, value: T) -> i32 {
		loop {
			self.next = self.next.wrapping_add(1).max(1);
			if !self.entries.contains_key(&self.next) {
				break;
			}
		}

		self.entries.insert(self.next, value);

		self.next
	}

	/// Run `body` against the value at `handle`.
	///
	/// # Errors
	///
	/// Returns [`INVALID_HANDLE`] when `handle` is unknown.
	pub fn with<R>(&self, handle: i32, body: impl FnOnce(&T) -> R) -> Result<R, CodedError> {
		self.entries
			.get(&handle)
			.map(body)
			.ok_or_else(|| self.unknown())
	}

	/// Run `body` against the mutable value at `handle`.
	///
	/// # Errors
	///
	/// Returns [`INVALID_HANDLE`] when `handle` is unknown.
	pub fn with_mut<R>(&mut self, handle: i32, body: impl FnOnce(&mut T) -> R) -> Result<R, CodedError> {
		self.entries
			.get_mut(&handle)
			.map(body)
			.ok_or_else(|| self.unknown())
	}

	/// Remove and return the value at `handle`.
	///
	/// # Errors
	///
	/// Returns [`INVALID_HANDLE`] when `handle` is unknown.
	pub fn take(&mut self, handle: i32) -> Result<T, CodedError> {
		self.entries.remove(&handle).ok_or_else(|| self.unknown())
	}

	/// Release `handle`, ignoring an unknown one.
	pub fn remove(&mut self, handle: i32) {
		self.entries.remove(&handle);
	}

	/// The coded error for a request referencing an unknown handle.
	fn unknown(&self) -> CodedError {
		CodedError::new(INVALID_HANDLE, format!("unknown {} handle", self.resource))
	}
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

	use super::*;

	#[test]
	fn store_returns_distinct_non_zero_handles() {
		let mut registry = HandleRegistry::new("thing");
		let first = registry.store(1u8);
		let second = registry.store(2u8);
		assert_ne!(first, 0);
		assert_ne!(second, 0);
		assert_ne!(first, second);
	}

	#[test]
	fn with_reads_a_stored_value() {
		let mut registry = HandleRegistry::new("thing");
		let handle = registry.store(7u8);
		assert!(matches!(registry.with(handle, |value| *value), Ok(7)));
	}

	#[test]
	fn with_mut_mutates_in_place() {
		let mut registry = HandleRegistry::new("thing");
		let handle = registry.store(1u8);
		assert!(matches!(registry.with_mut(handle, |value| *value += 8), Ok(())));
		assert!(matches!(registry.with(handle, |value| *value), Ok(9)));
	}

	#[test]
	fn take_removes_and_returns_the_value() {
		let mut registry = HandleRegistry::new("thing");
		let handle = registry.store(5u8);
		assert!(matches!(registry.take(handle), Ok(5)));
		assert!(registry.with(handle, |value| *value).is_err());
	}

	#[test]
	fn an_unknown_handle_is_rejected_with_a_stable_code() {
		let registry: HandleRegistry<u8> = HandleRegistry::new("thing");
		let code = registry
			.with(1, |value| *value)
			.err()
			.map(|error| error.code);
		assert_eq!(code, Some(INVALID_HANDLE.to_string()));
	}

	#[test]
	fn the_error_message_names_the_resource() {
		let registry: HandleRegistry<u8> = HandleRegistry::new("thing");
		let message = registry
			.with(1, |value| *value)
			.err()
			.map(|error| error.message);
		assert_eq!(message, Some("unknown thing handle".to_string()));
	}

	#[test]
	fn remove_frees_the_handle() {
		let mut registry = HandleRegistry::new("thing");
		let handle = registry.store(1u8);

		registry.remove(handle);

		assert!(registry.with(handle, |value| *value).is_err());
	}

	#[test]
	fn a_wrapped_counter_skips_zero_and_live_handles() {
		let mut registry = HandleRegistry::new("thing");
		let first = registry.store(1u8);

		registry.next = i32::MAX;

		let second = registry.store(2u8);
		assert_eq!(first, 1);
		assert_eq!(second, 2);
		assert!(matches!(registry.with(first, |value| *value), Ok(1)));
	}
}
