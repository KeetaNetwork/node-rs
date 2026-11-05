//! Turning a committed call's journal into Keeta blocks.
//!
//! The first block is the sequencer's, holding every `CREATE_IDENTIFIER`
//! of the call: creation always precedes use, so hoisting them is safe, and
//! it is what lets the engine know identifier addresses while contracts run
//! (see `next_identifier`). After that, consecutive operations on the same
//! account become one block, so the blocks keep the exact order the effects
//! happened in (a burn's `SEND` to the token lands before the token's supply
//! decrease, for example). The resulting list is what the sequencer would
//! publish as one vote staple.
//!
//! Signing is out of scope for the spike: blocks are built unsigned, but
//! with the signer they would need. Key-pair accounts (users) sign their
//! own blocks; identifier accounts (contracts, tokens) are signed by the
//! sequencer, which owns them.

use std::sync::Arc;

use keetanetwork_account::AccountPublicKey;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, BlockBuilder, BlockTime, CreateIdentifier, Operation, Permissions, SetInfo,
	TokenAdminSupply, UnsignedBlock,
};
use keetanetwork_crypto::hash::Hashable;
use num_bigint::{BigInt, BigUint};

use crate::address::{is_identifier, parse_account};
use crate::backend::BlockContext;
use crate::engine::EngineConfig;
use crate::error::EngineError;
use crate::state::{ChainState, LedgerOp};

pub(crate) fn build_blocks(
	state: &mut ChainState,
	config: &EngineConfig,
	block: &BlockContext,
	journal: &[LedgerOp],
) -> Result<Vec<UnsignedBlock>, EngineError> {
	let date = BlockTime::from_unix_millis(block.time_millis)
		.ok_or(EngineError::InvalidField { field: "block time", reason: "out of range".into() })?;

	let (creations, effects): (Vec<&LedgerOp>, Vec<&LedgerOp>) = journal
		.iter()
		.partition(|op| matches!(op, LedgerOp::CreateIdentifier { .. }));

	let mut blocks = Vec::new();
	let runs = std::iter::once(creations.as_slice())
		.filter(|creations| !creations.is_empty())
		.chain(effects.chunk_by(|a, b| a.account() == b.account()));
	for run in runs {
		let address = run[0].account();
		let account = account_ref(address)?;
		let signer = if account.to_keypair_type().is_identifier() {
			config.sequencer.clone()
		} else {
			account.clone()
		};
		let operations = run
			.iter()
			.copied()
			.map(to_operation)
			.collect::<Result<Vec<_>, _>>()?;

		let builder = BlockBuilder::default()
			.with_network(config.network)
			.with_account(account)
			.with_signer(signer)
			.with_date(date)
			.with_operations(operations);
		let builder = match state.heads.get(address) {
			Some(head) => builder.with_previous(*head),
			None => builder.as_opening(),
		};

		let unsigned = builder
			.build()
			.map_err(|source| EngineError::Block { account: address.to_string(), source })?;
		state.heads.insert(address.to_string(), unsigned.hash());
		blocks.push(unsigned);
	}
	Ok(blocks)
}

fn account_ref(address: &str) -> Result<AccountRef, EngineError> {
	Ok(Arc::new(parse_account(address)?))
}

fn amount(value: &BigUint) -> Amount {
	Amount::from(BigInt::from(value.clone()))
}

fn to_operation(op: &LedgerOp) -> Result<Operation, EngineError> {
	Ok(match op {
		LedgerOp::Send { to, token, amount: value, external, .. } => Operation::Send(keetanetwork_block::Send {
			to: account_ref(to)?,
			amount: amount(value),
			token: account_ref(token)?,
			external: external.clone(),
		}),
		LedgerOp::SetInfo { account, info } => Operation::SetInfo(SetInfo {
			name: info.name.clone(),
			description: info.description.clone(),
			metadata: info.metadata.clone(),
			// Identifier accounts must carry a default permission set.
			default_permission: is_identifier(account).then(Permissions::default),
		}),
		LedgerOp::CreateIdentifier { identifier, .. } => Operation::CreateIdentifier(CreateIdentifier {
			identifier: account_ref(identifier)?,
			create_arguments: None,
		}),
		LedgerOp::TokenSupply { amount: value, add, .. } => Operation::TokenAdminSupply(TokenAdminSupply {
			amount: amount(value),
			method: if *add {
				AdjustMethod::Add
			} else {
				AdjustMethod::Subtract
			},
		}),
	})
}
