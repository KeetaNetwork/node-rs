//! Shared account factories for integration tests.
#![allow(dead_code)] // each integration test binary uses a subset

use std::sync::Arc;

use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_block::AccountRef;
use keetanetwork_crypto::prelude::IntoSecret;

fn generate_base_account(seed_byte: u8) -> Account<KeyED25519> {
	let seed = [seed_byte; 32].into_secret();
	Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519))
		.expect("test account construction must succeed")
}

/// A deterministic keyed account.
pub fn generate_ed25519_ref(seed_byte: u8) -> AccountRef {
	Arc::new(GenericAccount::Ed25519(generate_base_account(seed_byte)))
}

/// Derive an identifier account from an existing owner.
pub fn generate_identifier_ref(owner: &AccountRef, key_type: KeyPairType, index: u32) -> AccountRef {
	let GenericAccount::Ed25519(account) = owner.as_ref() else {
		panic!("test owner must be ed25519");
	};
	Arc::new(
		account
			.generate_identifier(key_type, None, index)
			.expect("test identifier generation must succeed"),
	)
}
