//! Deterministic account, operation, and builder factories shared by
//! every Keetanetwork test suite.

use alloc::sync::Arc;

use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_crypto::prelude::IntoSecret;

use crate::amount::Amount;
use crate::builder::BlockBuilder;
use crate::operation::Send;
use crate::signer::AccountRef;
use crate::time::BlockTime;

fn base_account(seed_byte: u8) -> Account<KeyED25519> {
	let seed = [seed_byte; 32].into_secret();
	Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519))
		.expect("test account construction must succeed")
}

/// A deterministic ed25519 keyed account.
pub fn generate_ed25519_ref(seed_byte: u8) -> AccountRef {
	Arc::new(GenericAccount::Ed25519(base_account(seed_byte)))
}

/// A deterministic identifier account derived from a seed-byte owner.
///
/// Equivalent to `derive_identifier(&generate_ed25519_ref(seed_byte), ..)`;
/// kept for ergonomics in unit tests that don't otherwise need the owner.
pub fn generate_identifier_ref(seed_byte: u8, key_type: KeyPairType, index: u32) -> AccountRef {
	Arc::new(
		base_account(seed_byte)
			.generate_identifier(key_type, None, index)
			.expect("test identifier generation must succeed"),
	)
}

/// Derive an identifier account from an existing ed25519 owner.
///
/// # Panics
///
/// Panics if `owner` is not an ed25519 account. Identifier derivation is
/// only defined for that key type and this helper is intentionally
/// strict so test misuse fails loudly at the call site rather than
/// silently producing a divergent account.
pub fn derive_identifier(owner: &AccountRef, key_type: KeyPairType, index: u32) -> AccountRef {
	let GenericAccount::Ed25519(account) = owner.as_ref() else {
		panic!("derive_identifier requires an ed25519 owner");
	};
	Arc::new(
		account
			.generate_identifier(key_type, None, index)
			.expect("test identifier generation must succeed"),
	)
}

/// Pad an arbitrary-length test seed up to the 64-byte buffer expected by
/// `keetanetwork_account::doc_utils::create_*_test_keys`.
pub fn padded_seed(seed: &[u8]) -> [u8; 64] {
	let mut padded = [0u8; 64];
	let n = seed.len().min(padded.len());
	padded[..n].copy_from_slice(&seed[..n]);
	padded
}

/// Build a `(from, to)` pair of [`BlockTime`]s from unix-second offsets.
pub fn validity_blocktime(from_secs: i64, to_secs: i64) -> (BlockTime, BlockTime) {
	let from = BlockTime::from_unix_millis(from_secs * 1_000).expect("validity_from must be representable");
	let to = BlockTime::from_unix_millis(to_secs * 1_000).expect("validity_to must be representable");
	(from, to)
}

/// A minimal valid send operation for block builder tests.
pub fn sample_send() -> Send {
	Send {
		to: generate_ed25519_ref(2),
		amount: Amount::from(1u64),
		token: generate_identifier_ref(1, KeyPairType::TOKEN, 0),
		external: None,
	}
}

/// A minimal valid opening block builder for unit tests.
pub fn valid_block_builder() -> BlockBuilder {
	BlockBuilder::default()
		.with_network(0u8)
		.with_account(generate_ed25519_ref(1))
		.as_opening()
		.with_operation(sample_send())
}
