//! The binary interface between the engine and contracts.
//!
//! Both sides build against this module, so the layout is defined once.
//!
//! # Memory
//!
//! Contracts are sBPF v3 programs. The engine maps the usual sBPF regions:
//! read-only data and code, a stack, a [`HEAP_SIZE`] heap at [`HEAP_START`]
//! and the input at [`INPUT_START`]. The entrypoint receives a pointer to
//! the input in `r1` and returns `0` for success; anything else is a
//! contract error, whose message the contract reports through
//! [`syscall::ERROR`] first.
//!
//! # Input
//!
//! All integers are little-endian. Addresses take an [`ADDRESS_SLOT`]: the
//! [`ADDRESS_LEN`] bytes of an [`Address`], then zero padding.
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 40 | the contract being run |
//! | 40 | 40 | its caller: the account that signed the call, or the contract that invoked this one |
//! | 80 | 8 | block time, milliseconds since the Unix epoch (signed) |
//! | 88 | 8 | number of funds |
//! | 96 | 56 each | funds: token address slot, then the amount as a `u128` |
//! | | 8 | number of accounts |
//! | | | accounts, see below |
//! | | 8 | instruction data length |
//! | | | instruction data |
//!
//! Each account is an [`layout::ACCOUNT_HEADER`]-byte header followed by its
//! data, padded to a multiple of 8:
//!
//! | Offset | Size | Field |
//! | --- | --- | --- |
//! | 0 | 1 | writable (`1`) or read-only (`0`) |
//! | 1 | 1 | owned by the contract being run (`1`) or not (`0`) |
//! | 8 | 40 | owner: the contract whose state it is |
//! | 48 | 32 | id within the owner's state |
//! | 80 | 8 | data length |
//! | 88 | 8 | capacity: room reserved for the data |
//! | 96 | capacity | data |
//!
//! A contract may change the data, and the data length up to the capacity,
//! of accounts that are both writable and its own. The engine checks
//! everything else is unchanged when the contract returns.

/// Bytes in an [`Address`].
pub const ADDRESS_LEN: usize = 34;

/// Bytes an address takes in the input: [`ADDRESS_LEN`] padded to 8.
pub const ADDRESS_SLOT: usize = 40;

/// Virtual address of the heap.
pub const HEAP_START: u64 = 0x3_0000_0000;

/// Bytes of heap each contract invocation gets.
pub const HEAP_SIZE: usize = 256 * 1024;

/// Virtual address of the input.
pub const INPUT_START: u64 = 0x4_0000_0000;

/// Most accounts one instruction may list.
pub const MAX_ACCOUNTS: usize = 64;

/// Largest an account's data may be.
pub const MAX_ACCOUNT_SIZE: usize = 1024 * 1024;

/// How much a contract may grow one of its accounts in one invocation.
pub const ACCOUNT_GROWTH: usize = 10 * 1024;

/// Most bytes of return data.
pub const MAX_RETURN_DATA: usize = 64 * 1024;

/// Most bytes of instruction data.
pub const MAX_INSTRUCTION_DATA: usize = 64 * 1024;

/// Longest log line, event attribute or error message, in bytes.
pub const MAX_TEXT: usize = 4 * 1024;

/// Most bytes [`syscall::DECIMAL`] writes: `i128::MIN` in decimal.
pub const MAX_DECIMAL: usize = 40;

/// A 32-byte id naming one account within a contract's state.
pub type StateId = [u8; 32];

/// A Keeta account: its key type byte and public key, zero-padded to
/// [`ADDRESS_LEN`] bytes.
///
/// ECDSA keys (types 0 and 6) are 33 bytes, so their addresses use all 34
/// bytes. Every other type uses 33, and the last byte is zero.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; ADDRESS_LEN]);

impl Address {
	/// Bytes of the raw key-with-type form for a key type, or `None` for an
	/// unknown type.
	pub const fn raw_len(key_type: u8) -> Option<usize> {
		match key_type {
			0 | 6 => Some(34),
			1..=4 => Some(33),
			_ => None,
		}
	}

	/// An address from Keeta's raw key-with-type bytes. `None` if the length
	/// does not fit the key type.
	pub fn from_raw(raw: &[u8]) -> Option<Self> {
		let key_type = *raw.first()?;
		if Self::raw_len(key_type)? != raw.len() {
			return None;
		}
		let mut bytes = [0; ADDRESS_LEN];
		bytes[..raw.len()].copy_from_slice(raw);
		Some(Self(bytes))
	}

	/// The key type byte.
	pub const fn key_type(&self) -> u8 {
		self.0[0]
	}

	/// Keeta's raw key-with-type bytes, without padding. `None` if the key
	/// type is unknown or the padding is not zero.
	pub fn to_raw(&self) -> Option<&[u8]> {
		let len = Self::raw_len(self.key_type())?;
		if self.0[len..].iter().any(|byte| *byte != 0) {
			return None;
		}
		Some(&self.0[..len])
	}
}

impl core::fmt::Debug for Address {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "Address(")?;
		for byte in self.0 {
			write!(f, "{byte:02x}")?;
		}
		write!(f, ")")
	}
}

#[cfg(feature = "borsh")]
impl borsh::BorshSerialize for Address {
	fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
		writer.write_all(&self.0)
	}
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for Address {
	fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
		let mut bytes = [0; ADDRESS_LEN];
		reader.read_exact(&mut bytes)?;
		Ok(Self(bytes))
	}
}

/// Offsets into the input.
pub mod layout {
	/// The contract being run
	pub const CONTRACT: usize = 0;
	/// Its caller
	pub const CALLER: usize = 40;
	/// Block time in milliseconds
	pub const TIME_MILLIS: usize = 80;
	/// Number of funds
	pub const FUND_COUNT: usize = 88;
	/// First fund
	pub const FUNDS: usize = 96;
	/// Bytes per fund: token address slot and `u128` amount
	pub const FUND_SIZE: usize = 56;
	/// Offset of the amount within a fund
	pub const FUND_AMOUNT: usize = 40;

	/// Bytes of an account's header
	pub const ACCOUNT_HEADER: usize = 96;
	/// Writable flag, within an account header
	pub const ACCOUNT_WRITABLE: usize = 0;
	/// Owned-by-this-contract flag
	pub const ACCOUNT_OWN: usize = 1;
	/// Owner address slot
	pub const ACCOUNT_OWNER: usize = 8;
	/// State id
	pub const ACCOUNT_ID: usize = 48;
	/// Data length
	pub const ACCOUNT_DATA_LEN: usize = 80;
	/// Capacity
	pub const ACCOUNT_CAPACITY: usize = 88;

	/// `len` rounded up to a multiple of 8.
	pub const fn padded(len: usize) -> usize {
		(len + 7) & !7
	}
}

/// Host functions contracts call, by name.
///
/// sBPF v3 calls a host function through the [`syscall_hash`] of its name.
/// Arguments are passed in registers `r1` to `r5`. Pointers are virtual
/// addresses; an address argument points to [`ADDRESS_LEN`] bytes and an
/// amount argument to a little-endian `u128`. A failing host function
/// aborts the whole call, so they return only on success.
pub mod syscall {
	/// `(ptr, len)`: add a log line.
	pub const LOG: &str = "keeta_log";
	/// `(key_ptr, key_len, value_ptr, value_len)`: add an attribute to this
	/// invocation's event.
	pub const ATTRIBUTE: &str = "keeta_attribute";
	/// `(ptr, len)`: the message of the error the contract is about to
	/// return (or of its panic).
	pub const ERROR: &str = "keeta_error";
	/// `(ptr, len)`: set this invocation's return data.
	pub const SET_RETURN_DATA: &str = "keeta_set_return_data";
	/// `(ptr, max_len) -> len`: copy the return data of the last contract
	/// this one invoked, up to `max_len` bytes; returns its full length.
	pub const GET_RETURN_DATA: &str = "keeta_get_return_data";
	/// `(slices_ptr, count, out_ptr)`: SHA-256 of `count` `(ptr: u64, len:
	/// u64)` slices, written to 32 bytes at `out_ptr`.
	pub const SHA256: &str = "keeta_sha256";
	/// `(to, token, amount, external_ptr, external_len)`: `SEND` from the
	/// contract's account. `external_len` 0 means no `external`.
	pub const SEND: &str = "keeta_send";
	/// `(account, token, out_amount)`: an account's balance.
	pub const BALANCE: &str = "keeta_balance";
	/// `(token, out_amount) -> 1 | 0`: a token's supply, or 0 if there is no
	/// such token.
	pub const SUPPLY: &str = "keeta_supply";
	/// `(fields_ptr)`: `SET_INFO` on the contract's account; `fields_ptr`
	/// points to three slices: name, description, metadata.
	pub const SET_INFO: &str = "keeta_set_info";
	/// `(contract, metas_ptr, meta_count, data_ptr, data_len)`: run another
	/// contract. Each meta is `(index: u64, writable: u64)`, an account of
	/// this invocation to pass on.
	pub const INVOKE: &str = "keeta_invoke";
	/// `(value_ptr, signed, out_ptr) -> len`: the 16-byte little-endian
	/// integer at `value_ptr` (an `i128` if `signed` is 1, else a `u128`) in
	/// decimal, written to `out_ptr`, which has room for
	/// [`MAX_DECIMAL`](super::MAX_DECIMAL) bytes. Contracts write numbers
	/// with it instead of carrying code of their own for it.
	pub const DECIMAL: &str = "keeta_decimal";

	/// Every Keeta host function.
	pub const ALL: &[&str] = &[
		LOG,
		ATTRIBUTE,
		ERROR,
		SET_RETURN_DATA,
		GET_RETURN_DATA,
		SHA256,
		SEND,
		BALANCE,
		SUPPLY,
		SET_INFO,
		INVOKE,
		DECIMAL,
	];

	/// Host functions the Solana platform toolchain emits by itself (its
	/// `std` and compiler builtins), which the engine also provides.
	pub const PLATFORM: &[&str] =
		&["abort", "sol_panic_", "sol_log_", "sol_memcpy_", "sol_memmove_", "sol_memset_", "sol_memcmp_"];
}

/// The sBPF v3 key of a host function: Murmur3 (32-bit, seed 0) of its name.
pub const fn syscall_hash(name: &[u8]) -> u32 {
	const C1: u32 = 0xcc9e_2d51;
	const C2: u32 = 0x1b87_3593;
	let mut hash: u32 = 0;
	let mut i = 0;
	while i + 4 <= name.len() {
		let mut k = u32::from_le_bytes([name[i], name[i + 1], name[i + 2], name[i + 3]]);
		k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
		hash ^= k;
		hash = hash
			.rotate_left(13)
			.wrapping_mul(5)
			.wrapping_add(0xe654_6b64);
		i += 4;
	}
	let rest = name.len() - i;
	let mut k: u32 = 0;
	if rest == 3 {
		k ^= (name[i + 2] as u32) << 16;
	}
	if rest >= 2 {
		k ^= (name[i + 1] as u32) << 8;
	}
	if rest >= 1 {
		k ^= name[i] as u32;
		hash ^= k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
	}
	hash ^= name.len() as u32;
	hash ^= hash >> 16;
	hash = hash.wrapping_mul(0x85eb_ca6b);
	hash ^= hash >> 13;
	hash = hash.wrapping_mul(0xc2b2_ae35);
	hash ^= hash >> 16;
	hash
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hashes_match_the_sbpf_loader() {
		// Values from solana-sbpf's `hash_symbol_name`.
		assert_eq!(syscall_hash(b"keeta_log"), 0xd491_19c4);
		assert_eq!(syscall_hash(b"sol_log_"), 0x2075_59bd);
		assert_eq!(syscall_hash(b"abort"), 0xb6fc_1a11);
	}

	#[test]
	fn addresses_round_trip_through_raw_form() {
		let mut ed25519 = [7u8; 33];
		ed25519[0] = 1;
		let address = Address::from_raw(&ed25519).unwrap();
		assert_eq!(address.to_raw().unwrap(), ed25519);
		assert_eq!(address.0[33], 0);

		let mut secp = [9u8; 34];
		secp[0] = 0;
		assert_eq!(Address::from_raw(&secp).unwrap().to_raw().unwrap(), secp);

		assert!(Address::from_raw(&secp[..33]).is_none());
		let mut bad = address;
		bad.0[33] = 1;
		assert!(bad.to_raw().is_none());
	}

	#[test]
	fn layout_is_aligned() {
		assert_eq!(layout::FUNDS % 8, 0);
		assert_eq!(layout::FUND_SIZE % 8, 0);
		assert_eq!(layout::ACCOUNT_HEADER % 8, 0);
		assert_eq!(layout::padded(1), 8);
		assert_eq!(layout::padded(16), 16);
	}
}
