//! Fluent multi-account block builder.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, BlockHash, BlockPurpose, BlockTime, CreateIdentifier, Hashable,
	IdentifierCreateArguments, ManageCertificate, ModifyPermissions, Operation, Receive, Send, SetInfo, SetRep,
	TokenAdminModifyBalance, TokenAdminSupply,
};
use num_bigint::BigInt;
use snafu::ResultExt;

use crate::client::KeetaClient;
use crate::error::{AccountSnafu, ClientError};
use crate::model::{AccountOrPending, PendingAccount};

/// A deferred operation. Account operands stay as [`AccountOrPending`] so a
/// builder-issued [`PendingAccount`] can be referenced before it exists; they
/// resolve when the block is rendered in [`TransactionBuilder::build`].
enum PendingOp {
	Send {
		to: AccountOrPending,
		token: AccountOrPending,
		amount: Amount,
		external: Option<String>,
	},
	Receive {
		from: AccountOrPending,
		token: AccountOrPending,
		amount: Amount,
		exact: bool,
		forward: Option<AccountOrPending>,
	},
	CreateIdentifier {
		key_type: KeyPairType,
		create_arguments: Option<IdentifierCreateArguments>,
		handle: PendingAccount,
	},
	SetRep {
		to: AccountRef,
	},
	SetInfo(SetInfo),
	ModifyPermissions(ModifyPermissions),
	ModifyTokenSupply {
		amount: Amount,
		method: AdjustMethod,
	},
	ModifyTokenBalance {
		token: AccountOrPending,
		amount: Amount,
		method: AdjustMethod,
	},
	ManageCertificate(ManageCertificate),
	Raw(Operation),
}

/// A run of operations originated by one account, signed by one signer. Each
/// group renders to a single block.
struct Group {
	account: AccountRef,
	signer: AccountRef,
	ops: Vec<PendingOp>,
}

impl Group {
	fn new(account: AccountRef, signer: AccountRef) -> Self {
		Self { account, signer, ops: Vec::new() }
	}
}

/// A non-zero SEND accumulated for one `(recipient, token)` pair.
struct AggregatedSend {
	to: AccountRef,
	token: AccountRef,
	amount: BigInt,
}

/// Fluent builder for one or more accounts' blocks.
///
/// Operations accumulate against the active account group; switching the
/// active account with [`for_account`](Self::for_account) starts a new group,
/// and each group renders to one block. [`generate_identifier`](Self::generate_identifier)
/// returns a [`PendingAccount`] usable as an operand in later operations of the
/// same builder; its address resolves when [`build`](Self::build) seals the
/// blocks.
///
/// Create one with [`KeetaClient::builder`].
#[must_use = "a TransactionBuilder does nothing until `build` is called"]
pub struct TransactionBuilder<'a> {
	client: &'a KeetaClient,
	primary: AccountRef,
	groups: Vec<Group>,
	current: Group,
	initial_previous: Option<BlockHash>,
	purpose: Option<BlockPurpose>,
	date: Option<BlockTime>,
}

impl<'a> TransactionBuilder<'a> {
	/// Start a transaction whose default group is originated and signed by
	/// `account`.
	pub(crate) fn new(client: &'a KeetaClient, account: AccountRef) -> Self {
		Self {
			client,
			primary: Arc::clone(&account),
			groups: Vec::new(),
			current: Group::new(Arc::clone(&account), account),
			initial_previous: None,
			purpose: None,
			date: None,
		}
	}
}

impl TransactionBuilder<'_> {
	/// Switch the active group to `account`, signed by itself. Subsequent
	/// operations render into a new block for `account`.
	pub fn for_account(&mut self, account: &AccountRef) -> &mut Self {
		self.switch(Arc::clone(account), Arc::clone(account))
	}

	/// Switch the active group to `account`, signed by `signer` (delegated
	/// signing, e.g. operating as a created identifier whose parent signs).
	pub fn for_account_with_signer(&mut self, account: &AccountRef, signer: &AccountRef) -> &mut Self {
		self.switch(Arc::clone(account), Arc::clone(signer))
	}

	fn switch(&mut self, account: AccountRef, signer: AccountRef) -> &mut Self {
		let next = Group::new(account, signer);
		let previous = core::mem::replace(&mut self.current, next);
		if !previous.ops.is_empty() {
			self.groups.push(previous);
		}
		self
	}

	/// Append a SEND of `amount` of `token` to `to`.
	pub fn send(
		&mut self,
		to: impl Into<AccountOrPending>,
		token: impl Into<AccountOrPending>,
		amount: Amount,
	) -> &mut Self {
		self.push(PendingOp::Send { to: to.into(), token: token.into(), amount, external: None })
	}

	/// Append a SEND carrying `external` reference data. External sends are
	/// not aggregated with other sends to the same recipient and token.
	pub fn send_external(
		&mut self,
		to: impl Into<AccountOrPending>,
		token: impl Into<AccountOrPending>,
		amount: Amount,
		external: impl Into<String>,
	) -> &mut Self {
		self.push(PendingOp::Send { to: to.into(), token: token.into(), amount, external: Some(external.into()) })
	}

	/// Append a RECEIVE claiming `amount` of `token` sent by `from`.
	pub fn receive(
		&mut self,
		from: impl Into<AccountOrPending>,
		token: impl Into<AccountOrPending>,
		amount: Amount,
	) -> &mut Self {
		self.push(PendingOp::Receive { from: from.into(), token: token.into(), amount, exact: false, forward: None })
	}

	/// Append a RECEIVE with explicit `exact` matching and optional `forward`.
	pub fn receive_with(
		&mut self,
		from: impl Into<AccountOrPending>,
		token: impl Into<AccountOrPending>,
		amount: Amount,
		exact: bool,
		forward: Option<AccountOrPending>,
	) -> &mut Self {
		self.push(PendingOp::Receive { from: from.into(), token: token.into(), amount, exact, forward })
	}

	/// Append a block setting the originator's representative to `to`.
	pub fn set_rep(&mut self, to: &AccountRef) -> &mut Self {
		self.push(PendingOp::SetRep { to: Arc::clone(to) })
	}

	/// Set the originator's on-chain info. Repeated calls within the active
	/// group merge field-by-field into a single SET_INFO op.
	pub fn set_info(&mut self, info: SetInfo) -> &mut Self {
		for op in &mut self.current.ops {
			let PendingOp::SetInfo(existing) = op else {
				continue;
			};

			if !info.name.is_empty() {
				existing.name = info.name;
			}
			if !info.description.is_empty() {
				existing.description = info.description;
			}
			if !info.metadata.is_empty() {
				existing.metadata = info.metadata;
			}
			if info.default_permission.is_some() {
				existing.default_permission = info.default_permission;
			}

			return self;
		}

		self.push(PendingOp::SetInfo(info))
	}

	/// Append a block modifying the permissions granted by the originator.
	pub fn modify_permissions(&mut self, permissions: ModifyPermissions) -> &mut Self {
		self.push(PendingOp::ModifyPermissions(permissions))
	}

	/// Append a CREATE_IDENTIFIER of `key_type`, returning a handle to the
	/// not-yet-derived identifier address. The handle is usable as an operand
	/// in later operations and resolves during [`build`](Self::build).
	///
	/// `create_arguments` is required for multisig identifiers and otherwise
	/// omitted.
	pub fn generate_identifier(
		&mut self,
		key_type: KeyPairType,
		create_arguments: Option<IdentifierCreateArguments>,
	) -> PendingAccount {
		let handle = PendingAccount::default();
		self.current
			.ops
			.push(PendingOp::CreateIdentifier { key_type, create_arguments, handle: handle.clone() });
		handle
	}

	/// Append a block adjusting the supply of the originating token.
	pub fn modify_token_supply(&mut self, amount: Amount, method: AdjustMethod) -> &mut Self {
		self.push(PendingOp::ModifyTokenSupply { amount, method })
	}

	/// Append a block adjusting the originator's balance of `token`.
	pub fn modify_token_balance(
		&mut self,
		token: impl Into<AccountOrPending>,
		amount: Amount,
		method: AdjustMethod,
	) -> &mut Self {
		self.push(PendingOp::ModifyTokenBalance { token: token.into(), amount, method })
	}

	/// Append a block adding or removing a certificate on the originator.
	pub fn manage_certificate(&mut self, certificate: ManageCertificate) -> &mut Self {
		self.push(PendingOp::ManageCertificate(certificate))
	}

	/// Append an arbitrary operation. Escape hatch for operations without a
	/// dedicated method; rendered after the typed operations.
	pub fn with_operation(&mut self, operation: impl Into<Operation>) -> &mut Self {
		self.push(PendingOp::Raw(operation.into()))
	}

	/// Seed the primary account's first block `previous`, skipping its ledger
	/// head lookup. Useful for offline building or chaining after a
	/// not-yet-published block.
	pub fn with_previous(&mut self, previous: BlockHash) -> &mut Self {
		self.initial_previous = Some(previous);
		self
	}

	/// Override every block's purpose (defaults to the [`BlockPurpose`] default).
	pub fn with_purpose(&mut self, purpose: BlockPurpose) -> &mut Self {
		self.purpose = Some(purpose);
		self
	}

	/// Override every block's timestamp (defaults to the moment of build).
	pub fn with_date(&mut self, date: BlockTime) -> &mut Self {
		self.date = Some(date);
		self
	}

	fn push(&mut self, op: PendingOp) -> &mut Self {
		self.current.ops.push(op);
		self
	}

	/// Resolve each account group, derive any pending identifiers, and seal
	/// one signed block per group in group order. `previous` is chained per
	/// account within the builder, then the ledger head, then the opening.
	pub async fn build(&mut self) -> Result<Vec<Block>, ClientError> {
		let mut groups = core::mem::take(&mut self.groups);
		let next = Group::new(Arc::clone(&self.primary), Arc::clone(&self.primary));
		let current = core::mem::replace(&mut self.current, next);
		if !current.ops.is_empty() {
			groups.push(current);
		}

		let mut previous_by_account: BTreeMap<String, BlockHash> = BTreeMap::new();
		let mut blocks = Vec::with_capacity(groups.len());
		for group in &groups {
			let account_key = group.account.to_string();
			let previous = match previous_by_account.get(&account_key) {
				Some(hash) => Some(*hash),
				None => self.first_previous(&group.account).await?,
			};

			// A group whose operations all render away (e.g. only zero-amount
			// transfers) must not seal an empty, head-advancing no-op block.
			let operations = render_ops(group, previous)?;
			if operations.is_empty() {
				continue;
			}

			let block =
				self.client
					.seal_block(&group.account, &group.signer, previous, self.purpose, self.date, operations)?;
			previous_by_account.insert(account_key, block.hash());
			blocks.push(block);
		}

		Ok(blocks)
	}

	/// The `previous` for an account's first block: the [`with_previous`](Self::with_previous)
	/// seed (primary only), then the ledger head, then `None` (opening).
	async fn first_previous(&self, account: &AccountRef) -> Result<Option<BlockHash>, ClientError> {
		if let Some(previous) = self.initial_previous {
			if account.to_string() == self.primary.to_string() {
				return Ok(Some(previous));
			}
		}

		match self.client.head_block(account.to_string()).await? {
			Some(head) => Ok(Some(head.hash())),
			None => Ok(None),
		}
	}
}

/// The per-kind buckets a group's operations sort into. Filling them in a
/// single pass and draining them in field order yields the canonical render
/// order the ledger expects without re-scanning the operation list per kind.
#[derive(Default)]
struct RenderBuckets {
	creates: Vec<Operation>,
	external_sends: Vec<Operation>,
	aggregated_sends: BTreeMap<(String, String), AggregatedSend>,
	receives: Vec<Operation>,
	info: Vec<Operation>,
	set_rep: Vec<Operation>,
	supply: Vec<Operation>,
	certificates: Vec<Operation>,
	balance: Vec<Operation>,
	permissions: Vec<Operation>,
	raw: Vec<Operation>,
}

impl RenderBuckets {
	/// Derive the identifier for a `CreateIdentifier` op, fill its handle, and
	/// stage the create operation. `index` is positional within the group's
	/// creates so successive identifiers derive distinct addresses.
	fn push_create(
		&mut self,
		group: &Group,
		derive_previous: Option<&BlockHash>,
		key_type: KeyPairType,
		create_arguments: &Option<IdentifierCreateArguments>,
		handle: &PendingAccount,
	) -> Result<(), ClientError> {
		let index = self.creates.len() as u32;
		let derived = group
			.account
			.generate_identifier(key_type, derive_previous, index)
			.context(AccountSnafu)?;

		let derived: AccountRef = Arc::new(derived);
		handle.fill(Arc::clone(&derived));

		let create = CreateIdentifier { identifier: derived, create_arguments: create_arguments.clone() };
		self.creates.push(create.into());
		Ok(())
	}

	/// Stage a SEND: external sends pass through verbatim; plain sends to the
	/// same `(to, token)` accumulate into a single aggregated entry.
	fn push_send(
		&mut self,
		to: &AccountOrPending,
		token: &AccountOrPending,
		amount: &Amount,
		external: &Option<String>,
	) -> Result<(), ClientError> {
		let to = to.resolve()?;
		let token = token.resolve()?;

		if let Some(external) = external {
			let send = Send { to, token, amount: amount.clone(), external: Some(external.clone()) };
			self.external_sends.push(send.into());
			return Ok(());
		}

		let key = (to.to_string(), token.to_string());
		let entry = self
			.aggregated_sends
			.entry(key)
			.or_insert_with(|| AggregatedSend { to: Arc::clone(&to), token: Arc::clone(&token), amount: BigInt::ZERO });
		entry.amount += amount.as_bigint();
		Ok(())
	}

	/// Stage a RECEIVE, resolving its operands and optional forward target.
	fn push_receive(
		&mut self,
		from: &AccountOrPending,
		token: &AccountOrPending,
		amount: &Amount,
		exact: bool,
		forward: &Option<AccountOrPending>,
	) -> Result<(), ClientError> {
		let from = from.resolve()?;
		let token = token.resolve()?;
		let forward = match forward {
			Some(forward) => Some(forward.resolve()?),
			None => None,
		};

		let receive = Receive { amount: amount.clone(), token, from, exact, forward };
		self.receives.push(receive.into());
		Ok(())
	}

	/// Concatenate the buckets in render order, materializing the aggregated
	/// sends and dropping any that summed to zero.
	fn into_operations(self) -> Vec<Operation> {
		let aggregated = self
			.aggregated_sends
			.into_values()
			.filter(|send| send.amount != BigInt::ZERO)
			.map(|send| {
				Send { to: send.to, token: send.token, amount: Amount::from(send.amount), external: None }.into()
			});

		let mut operations = self.creates;
		operations.extend(self.external_sends);
		operations.extend(aggregated);
		operations.extend(self.receives);
		operations.extend(self.info);
		operations.extend(self.set_rep);
		operations.extend(self.supply);
		operations.extend(self.certificates);
		operations.extend(self.balance);
		operations.extend(self.permissions);
		operations.extend(self.raw);
		operations
	}
}

/// Render a group's deferred operations into concrete block operations in a
/// single pass, sorting each into its [`RenderBuckets`] slot and resolving any
/// pending operands and derived identifier addresses.
fn render_ops(group: &Group, previous: Option<BlockHash>) -> Result<Vec<Operation>, ClientError> {
	// An opening previous derives identifiers as `None`, matching
	// CreateIdentifier validation.
	let opening = group.account.to_opening_hash();
	let derive_previous = match &previous {
		Some(hash) if *hash != opening => Some(*hash),
		_ => None,
	};

	let mut buckets = RenderBuckets::default();
	for op in &group.ops {
		match op {
			PendingOp::CreateIdentifier { key_type, create_arguments, handle } => {
				buckets.push_create(group, derive_previous.as_ref(), *key_type, create_arguments, handle)?;
			}
			PendingOp::Send { to, token, amount, external } if *amount.as_bigint() != BigInt::ZERO => {
				buckets.push_send(to, token, amount, external)?;
			}
			PendingOp::Receive { from, token, amount, exact, forward } if *amount.as_bigint() != BigInt::ZERO => {
				buckets.push_receive(from, token, amount, *exact, forward)?;
			}
			PendingOp::ModifyTokenBalance { token, amount, method } => {
				let token = token.resolve()?;
				buckets
					.balance
					.push(TokenAdminModifyBalance { token, amount: amount.clone(), method: *method }.into());
			}
			PendingOp::SetInfo(info) => buckets.info.push(info.clone().into()),
			PendingOp::SetRep { to } => buckets.set_rep.push(SetRep { to: Arc::clone(to) }.into()),
			PendingOp::ModifyTokenSupply { amount, method } => buckets
				.supply
				.push(TokenAdminSupply { amount: amount.clone(), method: *method }.into()),
			PendingOp::ManageCertificate(certificate) => buckets.certificates.push(certificate.clone().into()),
			PendingOp::ModifyPermissions(permissions) => buckets.permissions.push(permissions.clone().into()),
			PendingOp::Raw(operation) => buckets.raw.push(operation.clone()),
			// Zero-amount sends and receives are dropped: they carry no value
			// and the ledger rejects empty transfers.
			PendingOp::Send { .. } | PendingOp::Receive { .. } => {}
		}
	}

	Ok(buckets.into_operations())
}

#[cfg(test)]
mod tests {
	use super::*;

	use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref};

	fn single_account_group(account: AccountRef, ops: Vec<PendingOp>) -> Group {
		Group { account: Arc::clone(&account), signer: account, ops }
	}

	#[test]
	fn render_orders_creates_first_with_stable_index() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x10);
		let token = generate_identifier_ref(0x20, KeyPairType::TOKEN, 0);
		let recipient = generate_ed25519_ref(0x30);
		let handle = PendingAccount::default();

		let ops = vec![
			PendingOp::Send {
				to: (&recipient).into(),
				token: (&token).into(),
				amount: Amount::from(5u64),
				external: None,
			},
			PendingOp::CreateIdentifier {
				key_type: KeyPairType::TOKEN,
				create_arguments: None,
				handle: handle.clone(),
			},
			PendingOp::SetRep { to: Arc::clone(&recipient) },
		];

		let group = single_account_group(Arc::clone(&account), ops);
		let rendered = render_ops(&group, None)?;
		assert!(matches!(rendered[0], Operation::CreateIdentifier(_)));
		assert!(matches!(rendered[1], Operation::Send(_)));
		assert!(matches!(rendered[2], Operation::SetRep(_)));

		let expected = account
			.generate_identifier(KeyPairType::TOKEN, None, 0)
			.context(AccountSnafu)?;
		assert_eq!(handle.get()?.to_string(), expected.to_string());
		Ok(())
	}

	#[test]
	fn render_aggregates_sends_per_recipient_and_token() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x11);
		let token = generate_identifier_ref(0x21, KeyPairType::TOKEN, 0);
		let recipient = generate_ed25519_ref(0x31);

		let ops = vec![
			PendingOp::Send {
				to: (&recipient).into(),
				token: (&token).into(),
				amount: Amount::from(3u64),
				external: None,
			},
			PendingOp::Send {
				to: (&recipient).into(),
				token: (&token).into(),
				amount: Amount::from(4u64),
				external: None,
			},
		];

		let group = single_account_group(account, ops);
		let rendered = render_ops(&group, None)?;
		assert_eq!(rendered.len(), 1);
		assert!(matches!(&rendered[0], Operation::Send(send) if send.amount == Amount::from(7u64)));
		Ok(())
	}

	#[test]
	fn render_keeps_external_sends_separate() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x12);
		let token = generate_identifier_ref(0x22, KeyPairType::TOKEN, 0);
		let recipient = generate_ed25519_ref(0x32);

		let ops = vec![
			PendingOp::Send {
				to: (&recipient).into(),
				token: (&token).into(),
				amount: Amount::from(3u64),
				external: None,
			},
			PendingOp::Send {
				to: (&recipient).into(),
				token: (&token).into(),
				amount: Amount::from(4u64),
				external: Some(String::from("ref")),
			},
		];

		let group = single_account_group(account, ops);
		let rendered = render_ops(&group, None)?;
		assert_eq!(rendered.len(), 2);
		Ok(())
	}

	#[test]
	fn render_resolves_pending_identifier_operand() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x14);
		let token = generate_identifier_ref(0x24, KeyPairType::TOKEN, 0);
		let handle = PendingAccount::default();

		let ops = vec![
			PendingOp::CreateIdentifier {
				key_type: KeyPairType::STORAGE,
				create_arguments: None,
				handle: handle.clone(),
			},
			PendingOp::Send { to: handle.into(), token: (&token).into(), amount: Amount::from(2u64), external: None },
		];
		let group = single_account_group(Arc::clone(&account), ops);
		let rendered = render_ops(&group, None)?;

		let expected = account
			.generate_identifier(KeyPairType::STORAGE, None, 0)
			.context(AccountSnafu)?;
		assert!(matches!(&rendered[1], Operation::Send(send) if send.to.to_string() == expected.to_string()));
		Ok(())
	}

	#[test]
	fn render_skips_zero_amount_sends() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x13);
		let token = generate_identifier_ref(0x23, KeyPairType::TOKEN, 0);
		let recipient = generate_ed25519_ref(0x33);

		let ops = vec![PendingOp::Send {
			to: (&recipient).into(),
			token: (&token).into(),
			amount: Amount::from(0u64),
			external: None,
		}];

		let group = single_account_group(account, ops);
		let rendered = render_ops(&group, None)?;
		assert!(rendered.is_empty());
		Ok(())
	}
}
