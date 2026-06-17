//! Fluent single-account block builder.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, BlockBuilder, BlockHash, BlockPurpose, BlockTime, CreateIdentifier,
	Hashable, IdentifierCreateArguments, ManageCertificate, ModifyPermissions, Operation, Receive, Send, SetInfo,
	SetRep, TokenAdminModifyBalance, TokenAdminSupply,
};
use snafu::ResultExt;

use crate::client::KeetaClient;
use crate::error::{BlockSnafu, ClientError};

/// Fluent builder for a single account's block.
///
/// Operations are accumulated synchronously against one originating account;
/// [`build`](Self::build) then resolves the block context and seals the block.
/// Each operation has a convenience method covering its common shape, plus a
/// typed `*_op` variant (where the operation carries rarely-used optional
/// fields) and the generic [`with_operation`](Self::with_operation) escape hatch.
///
/// Create one with [`KeetaClient::builder`].
#[must_use = "a TransactionBuilder does nothing until `build` is called"]
pub struct TransactionBuilder<'a> {
	client: &'a KeetaClient,
	account: AccountRef,
	operations: Vec<Operation>,
	previous: Option<BlockHash>,
	purpose: Option<BlockPurpose>,
	date: Option<BlockTime>,
}

impl<'a> TransactionBuilder<'a> {
	/// Start a transaction originated by `account` against `client`.
	pub(crate) fn new(client: &'a KeetaClient, account: AccountRef) -> Self {
		Self { client, account, operations: Vec::new(), previous: None, purpose: None, date: None }
	}
}

impl TransactionBuilder<'_> {
	/// Append a SEND of `amount` of `token` to `to`.
	///
	/// For external reference data, pass a [`Send`] to
	/// [`with_operation`](Self::with_operation).
	pub fn send(self, to: &AccountRef, token: &AccountRef, amount: Amount) -> Self {
		self.with_operation(Send { to: Arc::clone(to), amount, token: Arc::clone(token), external: None })
	}

	/// Append a RECEIVE claiming `amount` of `token` sent by `from`.
	///
	/// For exact-match or forwarding, pass a [`Receive`] to
	/// [`with_operation`](Self::with_operation).
	pub fn receive(self, from: &AccountRef, token: &AccountRef, amount: Amount) -> Self {
		self.with_operation(Receive {
			amount,
			token: Arc::clone(token),
			from: Arc::clone(from),
			exact: false,
			forward: None,
		})
	}

	/// Append a block setting the originator's representative to `to`.
	pub fn set_rep(self, to: &AccountRef) -> Self {
		self.with_operation(SetRep { to: Arc::clone(to) })
	}

	/// Append a block setting the originator's on-chain info.
	pub fn set_info(self, info: SetInfo) -> Self {
		self.with_operation(info)
	}

	/// Append a block modifying the permissions granted by the originator.
	pub fn modify_permissions(self, permissions: ModifyPermissions) -> Self {
		self.with_operation(permissions)
	}

	/// Append a block creating `identifier` under the originator.
	pub fn create_identifier(
		self,
		identifier: &AccountRef,
		create_arguments: Option<IdentifierCreateArguments>,
	) -> Self {
		self.with_operation(CreateIdentifier { identifier: Arc::clone(identifier), create_arguments })
	}

	/// Append a block adjusting the supply of the originating token.
	pub fn modify_token_supply(self, amount: Amount, method: AdjustMethod) -> Self {
		self.with_operation(TokenAdminSupply { amount, method })
	}

	/// Append a block adjusting the originator's balance of `token`.
	pub fn modify_token_balance(self, token: &AccountRef, amount: Amount, method: AdjustMethod) -> Self {
		self.with_operation(TokenAdminModifyBalance { token: Arc::clone(token), amount, method })
	}

	/// Append a block adding or removing a certificate on the originator.
	pub fn manage_certificate(self, certificate: ManageCertificate) -> Self {
		self.with_operation(certificate)
	}

	/// Append an arbitrary operation. Escape hatch for operations without a
	/// dedicated convenience method.
	pub fn with_operation(mut self, operation: impl Into<Operation>) -> Self {
		self.operations.push(operation.into());
		self
	}

	/// Override the resolved `previous` hash, skipping the ledger head lookup.
	///
	/// Useful when chaining a block after another not-yet-published block.
	pub fn with_previous(mut self, previous: BlockHash) -> Self {
		self.previous = Some(previous);
		self
	}

	/// Override the block purpose (defaults to the [`BlockPurpose`] default).
	pub fn with_purpose(mut self, purpose: BlockPurpose) -> Self {
		self.purpose = Some(purpose);
		self
	}

	/// Override the block timestamp (defaults to the moment of [`build`](Self::build)).
	pub fn with_date(mut self, date: BlockTime) -> Self {
		self.date = Some(date);
		self
	}

	/// Resolve the block context and seal the block.
	///
	/// `previous` is the override from [`with_previous`](Self::with_previous)
	/// when set, otherwise the originator's current head (the account opening
	/// hash when it has no blocks yet); network/subnet come from the client
	/// configuration. The originator's key seals the block, which is then
	/// ready to [`transmit`](KeetaClient::transmit).
	pub async fn build(self) -> Result<Block, ClientError> {
		let mut builder = self
			.client
			.apply_network(BlockBuilder::default())
			.with_account(Arc::clone(&self.account))
			.with_operations(self.operations);

		if let Some(purpose) = self.purpose {
			builder = builder.with_purpose(purpose);
		}
		if let Some(date) = self.date {
			builder = builder.with_date(date);
		}

		match self.previous {
			Some(previous) => builder = builder.with_previous(previous),
			None => match self.client.head_block(self.account.to_string()).await? {
				Some(head) => builder = builder.with_previous(head.hash()),
				None => builder = builder.as_opening(),
			},
		}

		let unsigned = builder.build().context(BlockSnafu)?;
		unsigned.sign().context(BlockSnafu)
	}
}
