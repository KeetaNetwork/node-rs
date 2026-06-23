//! WASI Preview 1 core-module ABI: a flat, handle-based C ABI over the shared
//! [`crate::pure`] surface, modeled on the JNI binding (opaque integer handles
//! into a registry, `alloc`/`dealloc` for guest memory, length-prefixed byte
//! transfers). Standard WASI P1 has sockets only over host-provided fds and no
//! outbound `connect` (nor `wasi:http`), so only the pure/offline surface is
//! exposed here; the host does any outbound dialing.
//!
//! ## Calling convention
//!
//! - The host calls [`keeta_alloc`] to reserve guest memory, writes input
//!   bytes/UTF-8 there, and passes `(ptr, len)` pairs.
//! - Object-producing calls return an `i32` handle (`0` on error; the failure
//!   detail is then available via [`keeta_last_error_code`] /
//!   [`keeta_last_error_message`]).
//! - Variable-length results are returned as a *bytes handle*; the host reads
//!   [`keeta_bytes_ptr`]/[`keeta_bytes_len`] then calls [`keeta_bytes_free`].
//! - Object handles are released with the matching `*_free`.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use keetanetwork_bindings::error::CodedError;
use keetanetwork_bindings::parse::adjust_method;
use keetanetwork_block::{AccountRef, Block, BlockBuilder, Operation, Permissions, UnsignedBlock};

use crate::pure;

/// Registry of live handles plus the last error, behind a single lock (the
/// WASI P1 guest is single-threaded, so contention never occurs).
#[derive(Default)]
struct State {
	next: i32,
	accounts: HashMap<i32, AccountRef>,
	blocks: HashMap<i32, Block>,
	bytes: HashMap<i32, Vec<u8>>,
	permissions: HashMap<i32, Permissions>,
	operations: HashMap<i32, Operation>,
	builders: HashMap<i32, BlockBuilder>,
	unsigned: HashMap<i32, UnsignedBlock>,
	last_error: Option<CodedError>,
}

impl State {
	fn allocate(&mut self) -> i32 {
		self.next += 1;
		self.next
	}
}

fn state() -> MutexGuard<'static, State> {
	static STATE: OnceLock<Mutex<State>> = OnceLock::new();
	let lock = STATE.get_or_init(|| Mutex::new(State::default()));
	// Recover from poisoning instead of panicking: a poisoned lock only means a
	// prior guest call unwound, and the registry stays structurally valid.
	lock.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Record `error` as the last failure and return the null handle.
fn fail(error: CodedError) -> i32 {
	state().last_error = Some(error);
	0
}

/// Store `bytes` as a result and return its handle.
fn store_bytes(bytes: Vec<u8>) -> i32 {
	let mut guard = state();
	let handle = guard.allocate();

	guard.bytes.insert(handle, bytes);
	handle
}

/// A value kind tracked in the handle registry. Centralizes the otherwise
/// per-type store/resolve/take/release boilerplate behind one set of generics:
/// each kind only names its registry table and its label for error messages.
trait Registered: Clone + Sized {
	/// Handle-kind label used in `INVALID_HANDLE` messages.
	const KIND: &'static str;

	/// The registry table holding values of this kind.
	fn table(state: &mut State) -> &mut HashMap<i32, Self>;
}

impl Registered for AccountRef {
	const KIND: &'static str = "account";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.accounts
	}
}

impl Registered for Block {
	const KIND: &'static str = "block";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.blocks
	}
}

impl Registered for Permissions {
	const KIND: &'static str = "permissions";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.permissions
	}
}

impl Registered for Operation {
	const KIND: &'static str = "operation";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.operations
	}
}

impl Registered for BlockBuilder {
	const KIND: &'static str = "builder";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.builders
	}
}

impl Registered for UnsignedBlock {
	const KIND: &'static str = "unsigned-block";

	fn table(state: &mut State) -> &mut HashMap<i32, Self> {
		&mut state.unsigned
	}
}

/// The `INVALID_HANDLE` error for a missing handle of kind `T`.
fn unknown_handle<T: Registered>() -> CodedError {
	CodedError::new("INVALID_HANDLE", format!("unknown {} handle", T::KIND))
}

/// Store `value` under a fresh handle and return it.
fn store<T: Registered>(value: T) -> i32 {
	let mut guard = state();
	let handle = guard.allocate();

	T::table(&mut guard).insert(handle, value);
	handle
}

/// Resolve a handle to a clone, recording an error and returning `None` when
/// the handle is unknown. The lock is released before recording the error so a
/// miss never re-enters [`state`].
fn resolve<T: Registered>(handle: i32) -> Option<T> {
	let value = T::table(&mut state()).get(&handle).cloned();
	if value.is_none() {
		fail(unknown_handle::<T>());
	}

	value
}

/// Remove and return a handle's value, recording an error and returning `None`
/// when the handle is unknown.
fn take<T: Registered>(handle: i32) -> Option<T> {
	let value = T::table(&mut state()).remove(&handle);
	if value.is_none() {
		fail(unknown_handle::<T>());
	}

	value
}

/// Release a handle, ignoring an unknown one.
fn release<T: Registered>(handle: i32) {
	T::table(&mut state()).remove(&handle);
}

/// Store an account and return its handle.
fn store_account(account: AccountRef) -> i32 {
	store(account)
}

/// Store a block and return its handle.
fn store_block(block: Block) -> i32 {
	store(block)
}

/// Store a permission set and return its handle.
fn store_permissions(permissions: Permissions) -> i32 {
	store(permissions)
}

/// Store an operation and return its handle.
fn store_operation(operation: Operation) -> i32 {
	store(operation)
}

/// Resolve an account handle, recording an error when it is unknown.
fn account(handle: i32) -> Option<AccountRef> {
	resolve(handle)
}

/// Resolve a block handle, recording an error when it is unknown.
fn block(handle: i32) -> Option<Block> {
	resolve(handle)
}

/// Resolve a permission set handle, recording an error when it is unknown.
fn permissions(handle: i32) -> Option<Permissions> {
	resolve(handle)
}

/// Apply a consuming transform to a builder handle, returning a fresh handle
/// (the prior handle is always consumed). Mirrors the JNI rebox pattern.
fn rebox_builder(handle: i32, apply: impl FnOnce(BlockBuilder) -> Option<BlockBuilder>) -> i32 {
	let Some(builder) = take::<BlockBuilder>(handle) else {
		return 0;
	};

	match apply(builder) {
		Some(builder) => store(builder),
		None => 0,
	}
}

/// Read a buffer of little-endian `i32` account handles and resolve each.
///
/// # Safety
/// See [`bytes_in`].
unsafe fn account_handles(ptr: i32, len: i32) -> Option<Vec<AccountRef>> {
	let bytes = bytes_in(ptr, len);
	if !bytes.len().is_multiple_of(4) {
		fail(CodedError::new("INVALID_HANDLE_LIST", "handle list must be 4-byte aligned"));
		return None;
	}

	bytes
		.chunks_exact(4)
		.map(|chunk| account(i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])))
		.collect()
}

/// Read a `(ptr, len)` guest buffer into an owned byte vector.
///
/// # Safety
/// `ptr` must point at `len` initialized bytes inside the guest's linear
/// memory (as returned by [`keeta_alloc`] and populated by the host).
unsafe fn bytes_in(ptr: i32, len: i32) -> Vec<u8> {
	if ptr == 0 || len <= 0 {
		return Vec::new();
	}

	core::slice::from_raw_parts(ptr as usize as *const u8, len as usize).to_vec()
}

/// Read a `(ptr, len)` guest buffer as UTF-8, recording an error and returning
/// `None` on invalid input.
///
/// # Safety
/// See [`bytes_in`].
unsafe fn string_in(ptr: i32, len: i32) -> Option<String> {
	match String::from_utf8(bytes_in(ptr, len)) {
		Ok(value) => Some(value),
		Err(_) => {
			fail(CodedError::new("INVALID_UTF8", "argument must be valid UTF-8"));
			None
		}
	}
}

/// Map a pure result into a bytes handle (`0` on error).
fn bytes_result(result: Result<Vec<u8>, CodedError>) -> i32 {
	match result {
		Ok(bytes) => store_bytes(bytes),
		Err(error) => fail(error),
	}
}

/// Map a pure string result into a bytes handle (`0` on error).
fn string_result(result: Result<String, CodedError>) -> i32 {
	bytes_result(result.map(String::into_bytes))
}

// ---------------------------------------------------------------------------
// Memory + result accessors
// ---------------------------------------------------------------------------

/// Reserve `len` bytes of guest memory and return a pointer the host can fill.
#[no_mangle]
pub extern "C" fn keeta_alloc(len: i32) -> i32 {
	if len <= 0 {
		return 0;
	}

	let mut buffer = Vec::<u8>::with_capacity(len as usize);
	let ptr = buffer.as_mut_ptr() as i32;

	core::mem::forget(buffer);

	ptr
}

/// Release memory previously returned by [`keeta_alloc`].
///
/// # Safety
/// `ptr`/`len` must come from a prior [`keeta_alloc`] call and not be reused.
#[no_mangle]
pub unsafe extern "C" fn keeta_dealloc(ptr: i32, len: i32) {
	if ptr == 0 || len <= 0 {
		return;
	}

	let _ = Vec::from_raw_parts(ptr as usize as *mut u8, 0, len as usize);
}

/// Pointer to a bytes handle's data, or `0` for an unknown handle.
#[no_mangle]
pub extern "C" fn keeta_bytes_ptr(handle: i32) -> i32 {
	state()
		.bytes
		.get(&handle)
		.map_or(0, |bytes| bytes.as_ptr() as i32)
}

/// Length of a bytes handle's data, or `0` for an unknown handle.
#[no_mangle]
pub extern "C" fn keeta_bytes_len(handle: i32) -> i32 {
	state()
		.bytes
		.get(&handle)
		.map_or(0, |bytes| bytes.len() as i32)
}

/// Release a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_bytes_free(handle: i32) {
	state().bytes.remove(&handle);
}

/// The last error code as a bytes handle (`0` when no error is pending).
#[no_mangle]
pub extern "C" fn keeta_last_error_code() -> i32 {
	let code = state().last_error.as_ref().map(|error| error.code.clone());
	code.map_or(0, |code| store_bytes(code.into_bytes()))
}

/// The last error message as a bytes handle (`0` when no error is pending).
#[no_mangle]
pub extern "C" fn keeta_last_error_message() -> i32 {
	let message = state()
		.last_error
		.as_ref()
		.map(|error| error.message.clone());

	message.map_or(0, |message| store_bytes(message.into_bytes()))
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

/// Generate a random 32-byte seed; returns a hex bytes handle.
#[no_mangle]
pub extern "C" fn keeta_generate_seed() -> i32 {
	string_result(pure::generate_seed())
}

/// Generate a BIP39 mnemonic; returns the words newline-joined as a bytes
/// handle.
#[no_mangle]
pub extern "C" fn keeta_generate_passphrase() -> i32 {
	string_result(pure::generate_passphrase().map(|words| words.join("\n")))
}

/// Derive an account from a hex seed; returns an account handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_from_seed(
	seed_ptr: i32,
	seed_len: i32,
	index: i32,
	algo_ptr: i32,
	algo_len: i32,
) -> i32 {
	let (Some(seed), Some(algorithm)) = (string_in(seed_ptr, seed_len), string_in(algo_ptr, algo_len)) else {
		return 0;
	};

	match pure::account_from_seed(&seed, index as u32, &algorithm) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// Derive an account from a hex private key; returns an account handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_from_private_key(
	key_ptr: i32,
	key_len: i32,
	algo_ptr: i32,
	algo_len: i32,
) -> i32 {
	let (Some(key), Some(algorithm)) = (string_in(key_ptr, key_len), string_in(algo_ptr, algo_len)) else {
		return 0;
	};

	match pure::account_from_private_key(&key, &algorithm) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// Derive an account from a newline-joined BIP39 mnemonic; returns an account
/// handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_from_passphrase(
	words_ptr: i32,
	words_len: i32,
	index: i32,
	algo_ptr: i32,
	algo_len: i32,
) -> i32 {
	let (Some(words), Some(algorithm)) = (string_in(words_ptr, words_len), string_in(algo_ptr, algo_len)) else {
		return 0;
	};
	let words = words.lines().map(String::from).collect();

	match pure::account_from_passphrase(words, index as u32, &algorithm) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// Build a read-only account from a hex public key; returns an account handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_from_public_key(
	key_ptr: i32,
	key_len: i32,
	algo_ptr: i32,
	algo_len: i32,
) -> i32 {
	let (Some(key), Some(algorithm)) = (string_in(key_ptr, key_len), string_in(algo_ptr, algo_len)) else {
		return 0;
	};

	match pure::account_from_public_key(&key, &algorithm) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// Build a read-only account from its textual address; returns an account
/// handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_from_address(address_ptr: i32, address_len: i32) -> i32 {
	let Some(address) = string_in(address_ptr, address_len) else {
		return 0;
	};
	match pure::account_from_address(&address) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// The account address as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_account_address(handle: i32) -> i32 {
	account(handle).map_or(0, |account| store_bytes(pure::account_address(&account).into_bytes()))
}

/// The account algorithm name as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_account_algorithm(handle: i32) -> i32 {
	account(handle).map_or(0, |account| store_bytes(pure::account_algorithm(&account).into_bytes()))
}

/// The type-prefixed public key (hex) as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_account_public_key(handle: i32) -> i32 {
	account(handle).map_or(0, |account| store_bytes(pure::account_public_key(&account).into_bytes()))
}

/// Sign a message; returns the signature as a bytes handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_sign(handle: i32, msg_ptr: i32, msg_len: i32) -> i32 {
	let Some(account) = account(handle) else {
		return 0;
	};

	let message = bytes_in(msg_ptr, msg_len);
	bytes_result(pure::account_sign(&account, &message))
}

/// Verify a signature; returns `1` for valid, `0` otherwise.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_verify(
	handle: i32,
	msg_ptr: i32,
	msg_len: i32,
	sig_ptr: i32,
	sig_len: i32,
) -> i32 {
	let Some(account) = account(handle) else {
		return 0;
	};
	let message = bytes_in(msg_ptr, msg_len);
	let signature = bytes_in(sig_ptr, sig_len);

	pure::account_verify(&account, &message, &signature) as i32
}

/// Encrypt to the account's public key; returns a bytes handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_encrypt(handle: i32, ptr: i32, len: i32) -> i32 {
	let Some(account) = account(handle) else {
		return 0;
	};

	let plaintext = bytes_in(ptr, len);
	bytes_result(pure::account_encrypt(&account, &plaintext))
}

/// Decrypt with the account's private key; returns a bytes handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_account_decrypt(handle: i32, ptr: i32, len: i32) -> i32 {
	let Some(account) = account(handle) else {
		return 0;
	};

	let ciphertext = bytes_in(ptr, len);
	bytes_result(pure::account_decrypt(&account, &ciphertext))
}

/// Derive an identifier account; returns an account handle. A zero-length
/// `prev` selects the account opening hash.
#[no_mangle]
pub unsafe extern "C" fn keeta_generate_identifier(
	handle: i32,
	kind_ptr: i32,
	kind_len: i32,
	prev_ptr: i32,
	prev_len: i32,
	index: i32,
) -> i32 {
	let Some(account) = account(handle) else {
		return 0;
	};
	let Some(kind) = string_in(kind_ptr, kind_len) else {
		return 0;
	};
	let kind = match keetanetwork_bindings::parse::identifier_type(&kind) {
		Ok(kind) => kind,
		Err(error) => return fail(CodedError::from(error)),
	};
	let previous = match identifier_previous(prev_ptr, prev_len) {
		Ok(previous) => previous,
		Err(error) => return fail(error),
	};

	match pure::generate_identifier(&account, kind, previous, index as u32) {
		Ok(account) => store_account(account),
		Err(error) => fail(error),
	}
}

/// Release an account handle.
#[no_mangle]
pub extern "C" fn keeta_account_free(handle: i32) {
	release::<AccountRef>(handle);
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// Decode a block from hex; returns a block handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_block_from_hex(ptr: i32, len: i32) -> i32 {
	let Some(value) = string_in(ptr, len) else {
		return 0;
	};
	match pure::block_from_hex(&value) {
		Ok(block) => store_block(block),
		Err(error) => fail(error),
	}
}

/// The block hash (hex) as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_block_hash(handle: i32) -> i32 {
	block(handle).map_or(0, |block| store_bytes(pure::block_hash(&block).into_bytes()))
}

/// The block transport encoding (hex) as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_block_to_hex(handle: i32) -> i32 {
	block(handle).map_or(0, |block| store_bytes(pure::block_to_hex(&block).into_bytes()))
}

/// Release a block handle.
#[no_mangle]
pub extern "C" fn keeta_block_free(handle: i32) {
	release::<Block>(handle);
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/// Build a permission set from newline-joined base flag names and a raw byte
/// buffer of external bit offsets; returns a permissions handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_permissions_from_flags(
	flags_ptr: i32,
	flags_len: i32,
	offsets_ptr: i32,
	offsets_len: i32,
) -> i32 {
	let Some(flags) = string_in(flags_ptr, flags_len) else {
		return 0;
	};
	let flags: Vec<String> = flags.lines().map(String::from).collect();
	let offsets = bytes_in(offsets_ptr, offsets_len);

	match pure::permissions_from_flags(&flags, &offsets) {
		Ok(permissions) => store_permissions(permissions),
		Err(error) => fail(error),
	}
}

/// Decode a permission set from `[base, external]` hex bitmaps; returns a
/// permissions handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_permissions_from_bitmaps(
	base_ptr: i32,
	base_len: i32,
	ext_ptr: i32,
	ext_len: i32,
) -> i32 {
	let (Some(base), Some(external)) = (string_in(base_ptr, base_len), string_in(ext_ptr, ext_len)) else {
		return 0;
	};

	match pure::permissions_from_bitmaps(&base, &external) {
		Ok(permissions) => store_permissions(permissions),
		Err(error) => fail(error),
	}
}

/// The base flag names as a newline-joined bytes handle.
#[no_mangle]
pub extern "C" fn keeta_permissions_flags(handle: i32) -> i32 {
	permissions(handle).map_or(0, |permissions| {
		store_bytes(
			pure::permissions_flag_names(&permissions)
				.join("\n")
				.into_bytes(),
		)
	})
}

/// The external bit offsets as a raw byte buffer bytes handle.
#[no_mangle]
pub extern "C" fn keeta_permissions_offsets(handle: i32) -> i32 {
	permissions(handle).map_or(0, |permissions| store_bytes(pure::permissions_offsets(&permissions)))
}

/// The `[base, external]` bitmaps as a newline-joined bytes handle.
#[no_mangle]
pub extern "C" fn keeta_permissions_bitmaps(handle: i32) -> i32 {
	permissions(handle).map_or(0, |permissions| {
		store_bytes(
			pure::permissions_bitmaps(&permissions)
				.join("\n")
				.into_bytes(),
		)
	})
}

/// Release a permissions handle.
#[no_mangle]
pub extern "C" fn keeta_permissions_free(handle: i32) {
	release::<Permissions>(handle);
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// A `SET_REP` operation to representative `to`; returns an operation handle.
#[no_mangle]
pub extern "C" fn keeta_op_set_rep(to: i32) -> i32 {
	account(to).map_or(0, |to| store_operation(pure::op_set_rep(to)))
}

/// A `SET_INFO` operation; `perms` may be `0` for no default permission.
#[no_mangle]
pub unsafe extern "C" fn keeta_op_set_info(
	name_ptr: i32,
	name_len: i32,
	desc_ptr: i32,
	desc_len: i32,
	meta_ptr: i32,
	meta_len: i32,
	perms: i32,
) -> i32 {
	let (Some(name), Some(description), Some(metadata)) =
		(string_in(name_ptr, name_len), string_in(desc_ptr, desc_len), string_in(meta_ptr, meta_len))
	else {
		return 0;
	};

	let default_permission = match perms {
		0 => None,
		handle => match permissions(handle) {
			Some(permissions) => Some(permissions),
			None => return 0,
		},
	};

	store_operation(pure::op_set_info(name, description, metadata, default_permission))
}

/// A `CREATE_IDENTIFIER` multisig operation; `signers` is a buffer of
/// little-endian `i32` account handles. Returns an operation handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_op_create_multisig(
	multisig: i32,
	signers_ptr: i32,
	signers_len: i32,
	quorum: i32,
) -> i32 {
	let Some(multisig) = account(multisig) else {
		return 0;
	};
	let Some(signers) = account_handles(signers_ptr, signers_len) else {
		return 0;
	};

	store_operation(pure::op_create_multisig(multisig, signers, quorum as u32))
}

/// A `MODIFY_PERMISSIONS` operation; `target` may be `0` for the block account.
#[no_mangle]
pub unsafe extern "C" fn keeta_op_modify_permissions(
	principal: i32,
	perms: i32,
	method_ptr: i32,
	method_len: i32,
	target: i32,
) -> i32 {
	let Some(principal) = account(principal) else {
		return 0;
	};
	let Some(permissions) = permissions(perms) else {
		return 0;
	};
	let Some(method) = string_in(method_ptr, method_len) else {
		return 0;
	};
	let method = match adjust_method(&method) {
		Ok(method) => method,
		Err(error) => return fail(CodedError::from(error)),
	};
	let target = match target {
		0 => None,
		handle => match account(handle) {
			Some(target) => Some(target),
			None => return 0,
		},
	};

	store_operation(pure::op_modify_permissions(principal, permissions, method, target))
}

/// Release an operation handle.
#[no_mangle]
pub extern "C" fn keeta_op_free(handle: i32) {
	release::<Operation>(handle);
}

// ---------------------------------------------------------------------------
// Offline block builder
// ---------------------------------------------------------------------------

/// Create an empty block builder; returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_new() -> i32 {
	store(BlockBuilder::default())
}

/// Set the block version (`1`/`2`); consumes and returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_version(handle: i32, version: i32) -> i32 {
	rebox_builder(handle, |builder| match pure::block_version(version as u32) {
		Ok(version) => Some(builder.with_version(version)),
		Err(error) => {
			fail(error);
			None
		}
	})
}

/// Set the network id; consumes and returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_network(handle: i32, network: i64) -> i32 {
	rebox_builder(handle, |builder| Some(builder.with_network(network)))
}

/// Set the originating account; consumes and returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_account(handle: i32, account_handle: i32) -> i32 {
	let Some(account) = account(account_handle) else {
		return rebox_builder(handle, |_| None);
	};

	rebox_builder(handle, |builder| Some(builder.with_account(account)))
}

/// Set a single-account signer; consumes and returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_signer(handle: i32, account_handle: i32) -> i32 {
	let Some(account) = account(account_handle) else {
		return rebox_builder(handle, |_| None);
	};

	rebox_builder(handle, |builder| Some(builder.with_signer(pure::signer_single(account))))
}

/// Set a multisig signer (`signers` is a buffer of little-endian `i32` account
/// handles); consumes and returns a builder handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_builder_with_multisig_signer(
	handle: i32,
	multisig: i32,
	signers_ptr: i32,
	signers_len: i32,
) -> i32 {
	let (Some(multisig), Some(signers)) = (account(multisig), account_handles(signers_ptr, signers_len)) else {
		return rebox_builder(handle, |_| None);
	};

	rebox_builder(handle, |builder| Some(builder.with_signer(pure::signer_multisig(multisig, signers))))
}

/// Set the previous block hash (32 bytes); consumes and returns a builder
/// handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_builder_with_previous(handle: i32, ptr: i32, len: i32) -> i32 {
	let previous = match identifier_previous(ptr, len) {
		Ok(Some(previous)) => previous,
		Ok(None) => {
			fail(CodedError::new("INVALID_HASH", "previous hash must be 32 bytes"));
			return rebox_builder(handle, |_| None);
		}
		Err(error) => {
			fail(error);
			return rebox_builder(handle, |_| None);
		}
	};

	rebox_builder(handle, |builder| Some(builder.with_previous(previous.into())))
}

/// Mark the block as an account opening (no previous); consumes and returns a
/// builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_as_opening(handle: i32) -> i32 {
	rebox_builder(handle, |builder| Some(builder.as_opening()))
}

/// Set the block timestamp (Unix milliseconds); consumes and returns a builder
/// handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_date(handle: i32, unix_millis: i64) -> i32 {
	rebox_builder(handle, |builder| match pure::block_time(unix_millis) {
		Ok(date) => Some(builder.with_date(date)),
		Err(error) => {
			fail(error);
			None
		}
	})
}

/// Append an operation (cloned); consumes and returns a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_with_operation(handle: i32, operation: i32) -> i32 {
	let Some(operation) = resolve::<Operation>(operation) else {
		return rebox_builder(handle, |_| None);
	};

	rebox_builder(handle, |builder| Some(builder.with_operation(operation)))
}

/// Build and validate the unsigned block, consuming the builder; returns an
/// unsigned-block handle.
#[no_mangle]
pub extern "C" fn keeta_builder_build(handle: i32) -> i32 {
	let Some(builder) = take::<BlockBuilder>(handle) else {
		return 0;
	};
	match pure::build_unsigned(builder) {
		Ok(unsigned) => store(unsigned),
		Err(error) => fail(error),
	}
}

/// Release a builder handle.
#[no_mangle]
pub extern "C" fn keeta_builder_free(handle: i32) {
	release::<BlockBuilder>(handle);
}

// ---------------------------------------------------------------------------
// Unsigned blocks
// ---------------------------------------------------------------------------

/// The unsigned block hash (hex) as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_unsigned_hash(handle: i32) -> i32 {
	match resolve::<UnsignedBlock>(handle) {
		Some(unsigned) => store_bytes(pure::unsigned_hash(&unsigned).into_bytes()),
		None => 0,
	}
}

/// Sign and seal the unsigned block, consuming it; returns a block handle.
#[no_mangle]
pub extern "C" fn keeta_unsigned_sign(handle: i32) -> i32 {
	let Some(unsigned) = take::<UnsignedBlock>(handle) else {
		return 0;
	};
	match pure::sign_unsigned(unsigned) {
		Ok(block) => store_block(block),
		Err(error) => fail(error),
	}
}

/// Release an unsigned-block handle.
#[no_mangle]
pub extern "C" fn keeta_unsigned_free(handle: i32) {
	release::<UnsignedBlock>(handle);
}

/// The signed block's raw transport bytes as a bytes handle.
#[no_mangle]
pub extern "C" fn keeta_block_to_bytes(handle: i32) -> i32 {
	block(handle).map_or(0, |block| store_bytes(pure::block_to_bytes(&block)))
}

// ---------------------------------------------------------------------------
// X.509 / certificate management
// ---------------------------------------------------------------------------

/// The `SHA3-256` hash (hex) of a hex-DER certificate; returns a bytes handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_certificate_hash(ptr: i32, len: i32) -> i32 {
	let Some(certificate) = string_in(ptr, len) else {
		return 0;
	};

	string_result(pure::certificate_hash(&certificate))
}

/// A `MANAGE_CERTIFICATE` add operation for a hex-DER certificate plus
/// newline-joined hex-DER intermediates; returns an operation handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_op_manage_certificate_add(
	cert_ptr: i32,
	cert_len: i32,
	intermediates_ptr: i32,
	intermediates_len: i32,
) -> i32 {
	let Some(certificate) = string_in(cert_ptr, cert_len) else {
		return 0;
	};
	let intermediates = match string_in(intermediates_ptr, intermediates_len) {
		Some(joined) if intermediates_len > 0 => joined.lines().map(String::from).collect(),
		Some(_) => Vec::new(),
		None => return 0,
	};

	match pure::op_manage_certificate_add(&certificate, &intermediates) {
		Ok(operation) => store_operation(operation),
		Err(error) => fail(error),
	}
}

/// A `MANAGE_CERTIFICATE` remove operation for a 32-byte hex hash; returns an
/// operation handle.
#[no_mangle]
pub unsafe extern "C" fn keeta_op_manage_certificate_remove(ptr: i32, len: i32) -> i32 {
	let Some(hash) = string_in(ptr, len) else {
		return 0;
	};

	match pure::op_manage_certificate_remove(&hash) {
		Ok(operation) => store_operation(operation),
		Err(error) => fail(error),
	}
}

/// Read an optional 32-byte previous-hash argument from guest memory.
///
/// # Safety
/// See [`bytes_in`].
unsafe fn identifier_previous(ptr: i32, len: i32) -> Result<Option<[u8; 32]>, CodedError> {
	if ptr == 0 || len == 0 {
		return Ok(None);
	}

	let bytes = bytes_in(ptr, len);
	let array: [u8; 32] = bytes
		.try_into()
		.map_err(|_| CodedError::new("INVALID_HASH", "previous hash must be 32 bytes"))?;

	Ok(Some(array))
}
