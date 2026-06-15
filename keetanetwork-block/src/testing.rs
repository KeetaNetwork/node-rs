//! Shared factories for unit tests.

use std::sync::Arc;

use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
use keetanetwork_crypto::prelude::IntoSecret;

use crate::amount::Amount;
use crate::builder::BlockBuilder;
use crate::operation::Send;
use crate::signer::AccountRef;

fn base_account(seed_byte: u8) -> Account<KeyED25519> {
	let seed = [seed_byte; 32].into_secret();
	Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519))
		.expect("test account construction must succeed")
}

/// A deterministic keyed account.
pub(crate) fn generate_ed25519_ref(seed_byte: u8) -> AccountRef {
	Arc::new(GenericAccount::Ed25519(base_account(seed_byte)))
}

/// A deterministic identifier account derived from [`generate_ed25519_ref`] with no
/// previous block (opening derivation).
pub(crate) fn generate_identifier_ref(seed_byte: u8, key_type: KeyPairType, index: u32) -> AccountRef {
	Arc::new(
		base_account(seed_byte)
			.generate_identifier(key_type, None, index)
			.expect("test identifier generation must succeed"),
	)
}

/// A minimal valid send operation for block builder tests.
pub(crate) fn sample_send() -> Send {
	Send {
		to: generate_ed25519_ref(2),
		amount: Amount::from(1u64),
		token: generate_identifier_ref(1, KeyPairType::TOKEN, 0),
		external: None,
	}
}

/// A minimal valid opening block builder for unit tests.
pub(crate) fn valid_block_builder() -> BlockBuilder {
	BlockBuilder::default()
		.with_network(0u8)
		.with_account(generate_ed25519_ref(1))
		.as_opening()
		.with_operation(sample_send())
}
