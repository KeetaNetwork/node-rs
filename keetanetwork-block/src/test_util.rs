//! Shared account factories for unit tests.

use std::sync::Arc;

use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_crypto::prelude::IntoSecret;

use crate::signer::AccountRef;

fn base_account(seed_byte: u8) -> Account<KeyED25519> {
	let seed = [seed_byte; 32].into_secret();
	Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519)).unwrap()
}

/// A deterministic keyed account.
pub(crate) fn ed25519(seed_byte: u8) -> AccountRef {
	Arc::new(GenericAccount::Ed25519(base_account(seed_byte)))
}

/// A deterministic identifier account derived from [`ed25519`] with no
/// previous block (opening derivation).
pub(crate) fn identifier(seed_byte: u8, key_type: KeyPairType, index: u32) -> AccountRef {
	Arc::new(
		base_account(seed_byte)
			.generate_identifier(key_type, None, index)
			.unwrap(),
	)
}
