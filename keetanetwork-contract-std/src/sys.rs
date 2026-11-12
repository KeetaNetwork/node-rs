//! Raw host functions (see [`crate::abi::syscall`]).
//!
//! On-chain each is a call through its [`syscall_hash`]; built for any other
//! target they panic, so contracts and this crate still compile (for tests
//! of pure logic, docs and lints).
//!
//! [`syscall_hash`]: crate::abi::syscall_hash

#![allow(unsafe_code, clippy::missing_safety_doc, missing_docs)]

macro_rules! syscalls {
	($( fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $symbol:expr; )*) => {$(
		#[inline(always)]
		#[cfg_attr(not(target_os = "solana"), allow(dead_code))]
		pub unsafe fn $name($($arg: $ty),*) -> $ret {
			#[cfg(target_os = "solana")]
			{
				const KEY: usize = $crate::abi::syscall_hash($symbol.as_bytes()) as usize;
				// SAFETY: sBPF v3 resolves a call to this constant as the host
				// function registered under the name; the engine refuses code
				// that calls anything it does not register.
				let function: extern "C" fn($($ty),*) -> $ret = unsafe { core::mem::transmute(KEY) };
				function($($arg),*)
			}
			#[cfg(not(target_os = "solana"))]
			{
				let _ = ($($arg,)*);
				panic!("{} is only available to contracts running in the engine", $symbol)
			}
		}
	)*};
}

use crate::abi::syscall;

syscalls! {
	fn keeta_log(ptr: *const u8, len: u64) -> u64 = syscall::LOG;
	fn keeta_attribute(key: *const u8, key_len: u64, value: *const u8, value_len: u64) -> u64 = syscall::ATTRIBUTE;
	fn keeta_error(ptr: *const u8, len: u64) -> u64 = syscall::ERROR;
	fn keeta_set_return_data(ptr: *const u8, len: u64) -> u64 = syscall::SET_RETURN_DATA;
	fn keeta_get_return_data(ptr: *mut u8, max_len: u64) -> u64 = syscall::GET_RETURN_DATA;
	fn keeta_sha256(slices: *const u8, count: u64, out: *mut u8) -> u64 = syscall::SHA256;
	fn keeta_send(to: *const u8, token: *const u8, amount: *const u8, external: *const u8, external_len: u64) -> u64 = syscall::SEND;
	fn keeta_balance(account: *const u8, token: *const u8, out: *mut u8) -> u64 = syscall::BALANCE;
	fn keeta_supply(token: *const u8, out: *mut u8) -> u64 = syscall::SUPPLY;
	fn keeta_set_info(fields: *const u8) -> u64 = syscall::SET_INFO;
	fn keeta_invoke(contract: *const u8, metas: *const u8, count: u64, data: *const u8, data_len: u64) -> u64 = syscall::INVOKE;
	fn keeta_decimal(value: *const u8, signed: u64, out: *mut u8) -> u64 = syscall::DECIMAL;
	fn keeta_panic(file: *const u8, len: u64, line: u64, column: u64) -> u64 = syscall::PANIC;
	fn keeta_memcpy(dest: *mut u8, src: *const u8, len: u64) -> u64 = syscall::MEMCPY;
	fn keeta_memmove(dest: *mut u8, src: *const u8, len: u64) -> u64 = syscall::MEMMOVE;
	fn keeta_memset(dest: *mut u8, byte: u64, len: u64) -> u64 = syscall::MEMSET;
	fn keeta_memcmp(a: *const u8, b: *const u8, len: u64, out: *mut i32) -> u64 = syscall::MEMCMP;
}

/// The memory functions the compiler calls, in place of the platform
/// toolchain's compiler builtins (which call Solana-named host functions).
/// The linker takes these first, so the builtins' copies are never linked.
#[cfg(target_os = "solana")]
mod mem {
	use super::{keeta_memcmp, keeta_memcpy, keeta_memmove, keeta_memset};

	#[no_mangle]
	unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
		// SAFETY: the compiler's contract for `memcpy`; the engine checks
		// both regions are mapped.
		unsafe { keeta_memcpy(dest, src, len as u64) };
		dest
	}

	#[no_mangle]
	unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, len: usize) -> *mut u8 {
		// SAFETY: as for `memcpy`.
		unsafe { keeta_memmove(dest, src, len as u64) };
		dest
	}

	#[no_mangle]
	unsafe extern "C" fn memset(dest: *mut u8, byte: i32, len: usize) -> *mut u8 {
		// SAFETY: as for `memcpy`.
		unsafe { keeta_memset(dest, byte as u8 as u64, len as u64) };
		dest
	}

	#[no_mangle]
	unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
		let mut order = 0;
		// SAFETY: as for `memcpy`; `order` is a valid `i32` to write.
		unsafe { keeta_memcmp(a, b, len as u64, &mut order) };
		order
	}
}
