//! JS `BlockBuilder`

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::str::FromStr;

use keetanetwork_block::{
	BlockBuilder as CoreBlockBuilder, BlockHash, BlockTime, BlockVersion, CreateIdentifier, IdentifierCreateArguments,
	MultisigCreateArguments, SetInfo, SetRep, Signer,
};
use num_bigint::BigInt;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::block::Block;
use crate::convert::{coded_error, JsResult};
use crate::permissions::{PermissionChange, Permissions};

/// A low-level block assembler. The core builder's mutators consume `self`, so
/// the staged builder is held in an `Option`.
#[wasm_bindgen]
pub struct BlockBuilder {
	inner: Option<CoreBlockBuilder>,
}

#[wasm_bindgen]
impl BlockBuilder {
	/// Start a block for operating `account` on `network`.
	#[wasm_bindgen(constructor)]
	pub fn new(network: u64, account: &Account) -> BlockBuilder {
		let inner = CoreBlockBuilder::default()
			.with_network(network)
			.with_account(account.inner());
		Self { inner: Some(inner) }
	}

	/// Set the block version (1 or 2).
	pub fn version(&mut self, version: u32) -> JsResult<()> {
		let version = block_version(version)?;
		self.stage(|builder| builder.with_version(version))
	}

	/// Chain onto `previous` (block hash hex).
	pub fn previous(&mut self, previous: String) -> JsResult<()> {
		let previous =
			BlockHash::from_str(&previous).map_err(|_| coded_error("INVALID_BLOCK_HASH", "block hash must be hex"))?;
		self.stage(|builder| builder.with_previous(previous))
	}

	/// Mark this as the account's opening block (no previous).
	pub fn opening(&mut self) -> JsResult<()> {
		self.stage(CoreBlockBuilder::as_opening)
	}

	/// Override the block timestamp (Unix milliseconds). Required where no
	/// system clock is available.
	#[wasm_bindgen(js_name = withDate)]
	pub fn with_date(&mut self, unix_millis: f64) -> JsResult<()> {
		let date = BlockTime::from_unix_millis(unix_millis as i64)
			.ok_or_else(|| coded_error("INVALID_DATE", "unix milliseconds out of range"))?;
		self.stage(|builder| builder.with_date(date))
	}

	/// Sign with a single `signer` account.
	#[wasm_bindgen(js_name = signerSingle)]
	pub fn signer_single(&mut self, signer: &Account) -> JsResult<()> {
		let signer = Signer::Single(signer.inner());
		self.stage(|builder| builder.with_signer(signer))
	}

	/// Sign with `multisig` using the member accounts in `members` (a quorum
	/// subset is allowed).
	#[wasm_bindgen(js_name = signerMultisig)]
	pub fn signer_multisig(&mut self, multisig: &Account, members: Vec<Account>) -> JsResult<()> {
		let signers = members
			.iter()
			.map(|member| Signer::Single(member.inner()))
			.collect();
		let signer = Signer::Multisig { address: multisig.inner(), signers };
		self.stage(|builder| builder.with_signer(signer))
	}

	/// Stage a CREATE_IDENTIFIER for `multisig` requiring `quorum` of `signers`.
	#[wasm_bindgen(js_name = opCreateMultisig)]
	pub fn op_create_multisig(&mut self, multisig: &Account, signers: Vec<Account>, quorum: u32) -> JsResult<()> {
		let signers = signers.iter().map(Account::inner).collect();
		let operation = CreateIdentifier {
			identifier: multisig.inner(),
			create_arguments: Some(IdentifierCreateArguments::Multisig(MultisigCreateArguments {
				signers,
				quorum: BigInt::from(quorum),
			})),
		};
		self.stage(|builder| builder.with_operation(operation))
	}

	/// Stage a MODIFY_PERMISSIONS block from `change`.
	#[wasm_bindgen(js_name = opModifyPermissions)]
	pub fn op_modify_permissions(&mut self, change: &PermissionChange) -> JsResult<()> {
		let operation = change.to_core();
		self.stage(|builder| builder.with_operation(operation))
	}

	/// Stage a SET_INFO block. `default_permission` is required for identifier
	/// accounts and rejected for keyed accounts.
	#[wasm_bindgen(js_name = opSetInfo)]
	pub fn op_set_info(
		&mut self,
		name: String,
		description: String,
		metadata: String,
		default_permission: Option<Permissions>,
	) -> JsResult<()> {
		let operation =
			SetInfo { name, description, metadata, default_permission: default_permission.map(|p| p.to_core()) };
		self.stage(|builder| builder.with_operation(operation))
	}

	/// Stage a SET_REP block delegating voting weight to `rep`.
	#[wasm_bindgen(js_name = opSetRep)]
	pub fn op_set_rep(&mut self, rep: &Account) -> JsResult<()> {
		let operation = SetRep { to: rep.inner() };
		self.stage(|builder| builder.with_operation(operation))
	}

	/// Build and sign the staged block, returning it for transport. Consumes
	/// the builder.
	pub fn sign(&mut self) -> JsResult<Block> {
		let builder = self.inner.take().ok_or_else(consumed)?;
		let unsigned = builder
			.build()
			.map_err(|error| coded_error("BLOCK", &error.to_string()))?;
		let signed = unsigned
			.sign()
			.map_err(|error| coded_error("BLOCK", &error.to_string()))?;
		Ok(Block::from(signed))
	}
}

impl BlockBuilder {
	/// Apply `change` to the staged builder, threading ownership back in.
	fn stage(&mut self, change: impl FnOnce(CoreBlockBuilder) -> CoreBlockBuilder) -> JsResult<()> {
		let builder = self.inner.take().ok_or_else(consumed)?;
		self.inner = Some(change(builder));
		Ok(())
	}
}

/// Parse a block version (`1` or `2`).
fn block_version(version: u32) -> JsResult<BlockVersion> {
	match version {
		1 => Ok(BlockVersion::V1),
		2 => Ok(BlockVersion::V2),
		_ => Err(coded_error("INVALID_BLOCK_VERSION", "block version must be 1 or 2")),
	}
}

/// The builder has already produced its block and can no longer be used.
fn consumed() -> wasm_bindgen::JsValue {
	coded_error("BUILDER_CONSUMED", "the block has already been built")
}
