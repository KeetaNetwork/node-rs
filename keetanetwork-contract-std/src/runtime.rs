//! What a contract sees while it runs: its [`Context`] and the host
//! functions it can call.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::borrow::Cow;

use crate::abi::{layout, Address, StateId, HEAP_SIZE, HEAP_START, MAX_RETURN_DATA};
use crate::sys;
use crate::text::Text;

/// A contract error: the call fails and every effect is undone. Its
/// message is text, not formatted (see [`crate::text`](mod@crate::text)(mod@crate::text)); a fixed message
/// costs no allocation.
#[derive(Clone, PartialEq, Eq)]
pub struct Error(Cow<'static, str>);

impl Error {
	/// The message.
	pub fn message(&self) -> &str {
		&self.0
	}
}

// Debug and Display are for tests and tools off-chain: a contract that
// never formats an error does not include them.
impl fmt::Debug for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl From<&'static str> for Error {
	fn from(message: &'static str) -> Self {
		Self(Cow::Borrowed(message))
	}
}

impl From<String> for Error {
	fn from(message: String) -> Self {
		Self(Cow::Owned(message))
	}
}

#[cfg(feature = "borsh")]
impl From<borsh::io::Error> for Error {
	fn from(error: borsh::io::Error) -> Self {
		// The kind, not the error's own message, which would need formatting.
		Self::from(match error.kind() {
			borsh::io::ErrorKind::UnexpectedEof => "bad data: it ends too soon",
			borsh::io::ErrorKind::InvalidData | borsh::io::ErrorKind::InvalidInput => "bad data: not a valid encoding",
			_ => "bad data",
		})
	}
}

/// Result of a contract operation.
pub type ContractResult<T = ()> = Result<T, Error>;

/// Fail the call with an error: a message, or a message made of pieces as
/// for [`text!`](crate::text!).
///
/// ```ignore
/// bail!("not initialized");
/// bail!("attach exactly ", price, " of the food token");
/// ```
///
/// Messages are not formatted: a `{` in the first piece is refused, since
/// `format!`-style arguments would not be filled in.
#[macro_export]
macro_rules! bail {
	($message:literal $(,)?) => {
		return Err($crate::Error::from($crate::__unformatted!($message)))
	};
	($first:literal, $($piece:expr),+ $(,)?) => {
		return Err($crate::Error::from($crate::text!($crate::__unformatted!($first), $($piece),+)))
	};
	($message:expr $(,)?) => {
		return Err($crate::Error::from($message))
	};
}

/// Fail the call with an error unless `condition` holds; the message as for
/// [`bail!`](crate::bail!).
#[macro_export]
macro_rules! ensure {
	($condition:expr, $($message:tt)+) => {
		if !$condition {
			$crate::bail!($($message)+);
		}
	};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __unformatted {
	($text:literal) => {{
		const _: () = assert!(
			!$crate::text::has_brace($text),
			"contract messages are not formatted: give values as pieces, as in bail!(\"text \", value)"
		);
		$text
	}};
}

/// Tokens attached to the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fund {
	/// Token address
	pub token: Address,
	/// Amount, in base units
	pub amount: u128,
}

/// One account the instruction lists: a piece of some contract's state.
///
/// The data lives in the input region the engine mapped, so changes are
/// seen by the engine directly. Only accounts that are writable and owned
/// by the running contract may change.
pub struct Account<'a> {
	header: *mut u8,
	_input: PhantomData<&'a mut [u8]>,
}

impl Account<'_> {
	fn read_u64(&self, offset: usize) -> u64 {
		// SAFETY: `header` points at an account header inside the input
		// region, which lives as long as the invocation.
		unsafe { core::ptr::read_unaligned(self.header.add(offset) as *const u64) }
	}

	/// The contract whose state this is.
	pub fn owner(&self) -> Address {
		// SAFETY: as in `read_u64`; an address slot holds ADDRESS_LEN bytes.
		unsafe { core::ptr::read_unaligned(self.header.add(layout::ACCOUNT_OWNER) as *const Address) }
	}

	/// Its id within the owner's state.
	pub fn id(&self) -> StateId {
		// SAFETY: as in `read_u64`.
		unsafe { core::ptr::read_unaligned(self.header.add(layout::ACCOUNT_ID) as *const StateId) }
	}

	/// Whether the instruction marked it writable.
	pub fn is_writable(&self) -> bool {
		// SAFETY: as in `read_u64`.
		unsafe { *self.header.add(layout::ACCOUNT_WRITABLE) != 0 }
	}

	/// Whether the running contract owns it.
	pub fn is_own(&self) -> bool {
		// SAFETY: as in `read_u64`.
		unsafe { *self.header.add(layout::ACCOUNT_OWN) != 0 }
	}

	/// Whether the running contract may change it.
	pub fn is_mutable(&self) -> bool {
		self.is_writable() && self.is_own()
	}

	/// Bytes of data.
	pub fn len(&self) -> usize {
		self.read_u64(layout::ACCOUNT_DATA_LEN) as usize
	}

	/// Whether the account has no data, which is the same as not existing.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Most bytes of data the account may hold in this invocation.
	pub fn capacity(&self) -> usize {
		self.read_u64(layout::ACCOUNT_CAPACITY) as usize
	}

	/// The data.
	pub fn data(&self) -> &[u8] {
		// SAFETY: the engine reserves `capacity >= len` bytes after the header.
		unsafe { core::slice::from_raw_parts(self.header.add(layout::ACCOUNT_HEADER), self.len()) }
	}

	/// The data, to change in place.
	pub fn data_mut(&mut self) -> ContractResult<&mut [u8]> {
		self.check_mutable()?;
		// SAFETY: as in `data`; `&mut self` keeps this the only view.
		Ok(unsafe { core::slice::from_raw_parts_mut(self.header.add(layout::ACCOUNT_HEADER), self.len()) })
	}

	fn check_mutable(&self) -> ContractResult {
		if !self.is_own() {
			return Err("this account belongs to another contract".into());
		}
		if !self.is_writable() {
			return Err("this account is read-only in this instruction".into());
		}
		Ok(())
	}

	/// Change the data length. New bytes are zero. Length 0 deletes the
	/// account once the call is committed.
	pub fn resize(&mut self, len: usize) -> ContractResult {
		self.check_mutable()?;
		let capacity = self.capacity();
		if len > capacity {
			crate::bail!("account data of ", len, " bytes exceeds the ", capacity, " available");
		}
		let old = self.len();
		if len > old {
			// SAFETY: `old..len` is within the reserved capacity.
			unsafe { core::ptr::write_bytes(self.header.add(layout::ACCOUNT_HEADER + old), 0, len - old) };
		}
		// SAFETY: as in `read_u64`.
		unsafe { core::ptr::write_unaligned(self.header.add(layout::ACCOUNT_DATA_LEN) as *mut u64, len as u64) };
		Ok(())
	}

	/// Replace the data.
	pub fn set(&mut self, bytes: &[u8]) -> ContractResult {
		self.resize(bytes.len())?;
		self.data_mut()?.copy_from_slice(bytes);
		Ok(())
	}

	/// Delete the account.
	pub fn clear(&mut self) -> ContractResult {
		self.resize(0)
	}

	/// The data decoded, or `None` while the account is empty.
	#[cfg(feature = "borsh")]
	pub fn load<T: borsh::BorshDeserialize>(&self) -> ContractResult<Option<T>> {
		if self.is_empty() {
			return Ok(None);
		}
		Ok(Some(borsh::from_slice(self.data())?))
	}

	/// Store a value as the data.
	#[cfg(feature = "borsh")]
	pub fn store<T: borsh::BorshSerialize>(&mut self, value: &T) -> ContractResult {
		self.set(&borsh::to_vec(value)?)
	}
}

/// Everything about the running invocation.
pub struct Context<'a> {
	/// The contract being run
	pub contract: Address,
	/// Who called it: the account that signed the call, or the contract that
	/// invoked this one
	pub caller: Address,
	/// Block time, milliseconds since the Unix epoch
	pub time_millis: i64,
	/// Tokens attached to the call, already in the contract's account
	pub funds: Vec<Fund>,
	/// The accounts the instruction lists, in its order
	pub accounts: Vec<Account<'a>>,
	/// The instruction data
	pub data: &'a [u8],
}

impl<'a> Context<'a> {
	/// Read the input the engine mapped at `input`.
	///
	/// # Safety
	///
	/// `input` must point at an input region laid out as in [`crate::abi`],
	/// valid for `'a`.
	pub unsafe fn from_input(input: *mut u8) -> Self {
		let u64_at = |offset: usize| unsafe { core::ptr::read_unaligned(input.add(offset) as *const u64) };
		let address_at = |offset: usize| unsafe { core::ptr::read_unaligned(input.add(offset) as *const Address) };

		let fund_count = u64_at(layout::FUND_COUNT) as usize;
		let funds = (0..fund_count)
			.map(|index| {
				let at = layout::FUNDS + index * layout::FUND_SIZE;
				let amount =
					unsafe { core::ptr::read_unaligned(input.add(at + layout::FUND_AMOUNT) as *const [u8; 16]) };
				Fund { token: address_at(at), amount: u128::from_le_bytes(amount) }
			})
			.collect();

		let mut offset = layout::FUNDS + fund_count * layout::FUND_SIZE;
		let account_count = u64_at(offset) as usize;
		offset += 8;
		let mut accounts = Vec::with_capacity(account_count);
		for _ in 0..account_count {
			let capacity = u64_at(offset + layout::ACCOUNT_CAPACITY) as usize;
			accounts.push(Account { header: unsafe { input.add(offset) }, _input: PhantomData });
			offset += layout::ACCOUNT_HEADER + layout::padded(capacity);
		}

		let data_len = u64_at(offset) as usize;
		let data = unsafe { core::slice::from_raw_parts(input.add(offset + 8), data_len) };

		Self {
			contract: address_at(layout::CONTRACT),
			caller: address_at(layout::CALLER),
			time_millis: u64_at(layout::TIME_MILLIS) as i64,
			funds,
			accounts,
			data,
		}
	}

	/// Block time in whole seconds since the Unix epoch.
	pub fn time_seconds(&self) -> u64 {
		self.time_millis.max(0) as u64 / 1000
	}

	/// The `index`th account.
	pub fn account(&mut self, index: usize) -> ContractResult<&mut Account<'a>> {
		let count = self.accounts.len();
		self.accounts.get_mut(index).ok_or_else(|| {
			Error::from(crate::text!("the instruction lists ", count, " accounts, needs at least ", index + 1))
		})
	}

	/// The `index`th account, checked to be this contract's account `id`.
	pub fn own_account(&mut self, index: usize, id: &StateId) -> ContractResult<&mut Account<'a>> {
		let contract = self.contract;
		let account = self.account(index)?;
		if account.owner() != contract || account.id() != *id {
			crate::bail!("account ", index, " is not the one this instruction needs");
		}
		Ok(account)
	}

	/// Fail unless no tokens are attached.
	pub fn no_funds(&self) -> ContractResult {
		if self.funds.is_empty() {
			Ok(())
		} else {
			Err("this action takes no funds".into())
		}
	}
}

// Host functions ------------------------------------------------------------

fn slices<const N: usize>(parts: [&[u8]; N]) -> [[u64; 2]; N] {
	parts.map(|part| [part.as_ptr() as u64, part.len() as u64])
}

/// Add a log line to the call's logs.
pub fn log(message: &str) {
	// SAFETY: the pointer and length describe `message`.
	unsafe { sys::keeta_log(message.as_ptr(), message.len() as u64) };
}

/// Add an attribute to this invocation's event: `value` is any [`Text`]
/// (strings, integers, `bool`).
pub fn attribute(key: &str, value: impl Text) {
	let mut text = String::new();
	value.write_text(&mut text);
	let value = text;
	// SAFETY: the pointers and lengths describe `key` and `value`.
	unsafe { sys::keeta_attribute(key.as_ptr(), key.len() as u64, value.as_ptr(), value.len() as u64) };
}

/// Return data to whoever called this contract (the client, or an invoking
/// contract through [`return_data`]).
pub fn set_return_data(data: &[u8]) {
	// SAFETY: the pointer and length describe `data`.
	unsafe { sys::keeta_set_return_data(data.as_ptr(), data.len() as u64) };
}

/// The return data of the last contract this one invoked.
pub fn return_data() -> Vec<u8> {
	// The heap is never freed, so ask for the length first and allocate
	// only that much.
	// SAFETY: with `max_len` 0 nothing is written.
	let len = (unsafe { sys::keeta_get_return_data(core::ptr::null_mut(), 0) } as usize).min(MAX_RETURN_DATA);
	let mut buffer = vec![0u8; len];
	// SAFETY: the buffer has room for `len` bytes.
	unsafe { sys::keeta_get_return_data(buffer.as_mut_ptr(), len as u64) };
	buffer
}

/// SHA-256 of the concatenation of `parts`. Off-chain it is computed
/// directly, so clients can use contracts' account-naming helpers.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
	#[cfg(target_os = "solana")]
	{
		// Up to eight parts (as seeds usually are) described on the stack.
		const ON_STACK: usize = 8;
		let mut stack = [[0u64; 2]; ON_STACK];
		let heap: Vec<[u64; 2]>;
		let slices: &[[u64; 2]] = if parts.len() <= ON_STACK {
			for (slice, part) in stack.iter_mut().zip(parts) {
				*slice = [part.as_ptr() as u64, part.len() as u64];
			}
			&stack[..parts.len()]
		} else {
			heap = parts
				.iter()
				.map(|part| [part.as_ptr() as u64, part.len() as u64])
				.collect();
			&heap
		};
		let mut out = [0u8; 32];
		// SAFETY: `slices` describes `parts`; `out` has room for 32 bytes.
		unsafe { sys::keeta_sha256(slices.as_ptr() as *const u8, slices.len() as u64, out.as_mut_ptr()) };
		out
	}
	#[cfg(not(target_os = "solana"))]
	{
		use sha2::Digest;
		let mut hasher = sha2::Sha256::new();
		for part in parts {
			hasher.update(part);
		}
		hasher.finalize().into()
	}
}

/// The id of an account named by `seeds`: SHA-256 of their concatenation.
/// The engine's `state_id` computes the same, so clients can name accounts.
pub fn state_id(seeds: &[&[u8]]) -> StateId {
	sha256(seeds)
}

/// `SEND` from the contract's account. `external` is the memo wallets and
/// anchors use to correlate payments.
pub fn send(to: &Address, token: &Address, amount: u128, external: Option<&str>) {
	let amount = amount.to_le_bytes();
	let external = external.unwrap_or_default();
	// SAFETY: every pointer refers to a live value of the documented size.
	unsafe {
		sys::keeta_send(to.0.as_ptr(), token.0.as_ptr(), amount.as_ptr(), external.as_ptr(), external.len() as u64)
	};
}

/// An account's balance of a token.
pub fn balance(account: &Address, token: &Address) -> u128 {
	let mut out = [0u8; 16];
	// SAFETY: the addresses are ADDRESS_LEN bytes; `out` has room for a u128.
	unsafe { sys::keeta_balance(account.0.as_ptr(), token.0.as_ptr(), out.as_mut_ptr()) };
	u128::from_le_bytes(out)
}

/// A token's total supply, or `None` if there is no such token.
pub fn supply(token: &Address) -> Option<u128> {
	let mut out = [0u8; 16];
	// SAFETY: as in `balance`.
	let found = unsafe { sys::keeta_supply(token.0.as_ptr(), out.as_mut_ptr()) };
	(found == 1).then(|| u128::from_le_bytes(out))
}

/// `SET_INFO` on the contract's account: one of the call's ledger effects.
pub fn set_info(name: &str, description: &str, metadata: &str) {
	let fields = slices([name.as_bytes(), description.as_bytes(), metadata.as_bytes()]);
	// SAFETY: `fields` describes three live slices.
	unsafe { sys::keeta_set_info(fields.as_ptr() as *const u8) };
}

/// Run `contract` with some of this invocation's accounts, given as
/// `(index into ctx.accounts, writable)`. A writable account must be
/// writable here too. The callee's caller is this contract. If the callee
/// fails, the whole call fails, so this returns only on success; read what
/// it returned with [`return_data`]. Accounts it changed are updated in
/// place.
pub fn invoke(contract: &Address, accounts: &[(usize, bool)], data: &[u8]) {
	let metas: Vec<[u64; 2]> = accounts
		.iter()
		.map(|(index, writable)| [*index as u64, *writable as u64])
		.collect();
	// SAFETY: every pointer and length describes a live value.
	unsafe {
		sys::keeta_invoke(
			contract.0.as_ptr(),
			metas.as_ptr() as *const u8,
			metas.len() as u64,
			data.as_ptr(),
			data.len() as u64,
		)
	};
}

// Entrypoint support ---------------------------------------------------------

/// Run `process` over the input, reporting its error to the engine.
///
/// # Safety
///
/// `input` must be the input region the engine passed to the entrypoint.
#[doc(hidden)]
pub unsafe fn run(input: *mut u8, process: impl FnOnce(&mut Context<'_>) -> ContractResult) -> u64 {
	// SAFETY: forwarded from the caller.
	let mut context = unsafe { Context::from_input(input) };
	match process(&mut context) {
		Ok(()) => 0,
		Err(error) => {
			let message = error.message();
			// SAFETY: the pointer and length describe `message`.
			unsafe { sys::keeta_error(message.as_ptr(), message.len() as u64) };
			1
		}
	}
}

/// Report a panic as the contract's error: its message when that is plain
/// text, then where it happened, which the engine writes out. A message
/// with arguments (`panic!("{x}")`, or the standard library's own, such as
/// an index out of bounds) is left out: writing it would need Rust's
/// formatting code in every contract.
#[doc(hidden)]
pub fn report_panic(info: &core::panic::PanicInfo<'_>) {
	let message = info.message().as_str().unwrap_or("panicked");
	// SAFETY: the pointer and length describe `message`.
	unsafe { sys::keeta_error(message.as_ptr(), message.len() as u64) };
	if let Some(location) = info.location() {
		let file = location.file();
		// SAFETY: the pointer and length describe `file`. The engine ends
		// the call here, with the message above.
		unsafe { sys::keeta_panic(file.as_ptr(), file.len() as u64, location.line() as u64, location.column() as u64) };
	}
}

/// A bump allocator over the heap region. sBPF programs cannot have
/// writable statics, so the position lives in the heap's first 8 bytes.
/// Memory is never freed: an invocation is short.
#[doc(hidden)]
pub struct BumpAllocator;

// SAFETY: hands out non-overlapping, aligned ranges of the heap region, or
// null when it is used up.
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
	unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
		let start = HEAP_START as usize;
		let position = start as *mut usize;
		// SAFETY: the heap's first word is reserved for the position; the
		// engine zeroes the heap, so it starts at 0.
		let current = match unsafe { *position } {
			0 => start + core::mem::size_of::<usize>(),
			current => current,
		};
		let aligned = (current + layout.align() - 1) & !(layout.align() - 1);
		let Some(end) = aligned.checked_add(layout.size()) else {
			return core::ptr::null_mut();
		};
		if end > start + HEAP_SIZE {
			return core::ptr::null_mut();
		}
		// SAFETY: as above.
		unsafe { *position = end };
		aligned as *mut u8
	}

	unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

/// Declare a contract's entrypoint: `process(&mut Context) -> ContractResult`.
///
/// Also installs the heap allocator and reports panics as contract errors.
#[macro_export]
macro_rules! entrypoint {
	($process:path) => {
		#[cfg(target_os = "solana")]
		#[no_mangle]
		pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
			unsafe { $crate::run(input, $process) }
		}

		#[cfg(target_os = "solana")]
		#[global_allocator]
		static ALLOCATOR: $crate::BumpAllocator = $crate::BumpAllocator;

		#[cfg(target_os = "solana")]
		#[no_mangle]
		fn custom_panic(info: &core::panic::PanicInfo<'_>) {
			$crate::report_panic(info)
		}

		// Off-chain (host builds for tests and clients) there is no
		// entrypoint; this still checks `process`'s signature.
		#[cfg(not(target_os = "solana"))]
		const _: fn(&mut $crate::Context<'_>) -> $crate::ContractResult = $process;
	};
}
