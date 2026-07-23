//! Signer-bound high-level facade over [`KeetaClient`].

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::{AccountPublicKey, KeyPairType};
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, BlockHash, IdentifierCreateArguments, ManageCertificate,
	ModifyPermissions, ModifyPermissionsPrincipal, Operation, Receive, Send, SetInfo,
};
use keetanetwork_vote::{VoteBlockHash, VoteQuote, VoteStaple};

use crate::builder::TransactionBuilder;
use crate::client::{is_ledger_code, KeetaClient};
use crate::error::ClientError;
use crate::model::{
	AccountState, Acl, BlockEffects, Certificate, ChainQuery, HistoryEntry, HistoryQuery, TokenBalance, TransmitOptions,
};
use crate::swap::{AcceptSwapRequest, CreateSwapRequest, SwapTokenAmount};
use crate::transport::LedgerSide;

#[cfg(feature = "http")]
use {crate::config::ClientConfig, crate::network::Network, crate::rep::RepEndpoint, num_bigint::BigInt};

use crate::genesis::{generate_initial_vote_staple, InitializeNetwork};

/// A [`KeetaClient`] bound to a signer (and optionally a distinct operating
/// account), exposing account-scoped reads and convenience writes.
///
/// Reads default to the bound account. Writes originate blocks for the bound
/// account, signed and fee-paid by the bound signer. Constructed read-only
/// (no signer) it answers queries but rejects writes with
/// [`ClientError::SignerRequired`].
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use keetanetwork_account::GenericAccount;
/// use keetanetwork_account::doc_utils::create_ed25519_test_keys;
/// use keetanetwork_block::AccountRef;
/// use keetanetwork_client::{Network, UserClient};
///
/// let (_, _, key) = create_ed25519_test_keys(None);
/// let signer: AccountRef = Arc::new(GenericAccount::Ed25519(key));
///
/// let writer = UserClient::from_network(Network::Test, Some(signer))?;
/// assert!(!writer.is_read_only());
///
/// let reader = UserClient::from_network(Network::Test, None)?;
/// assert!(reader.is_read_only());
/// # Ok::<(), keetanetwork_client::ClientError>(())
/// ```
pub struct UserClient {
	client: KeetaClient,
	account: Option<AccountRef>,
	signer: Option<AccountRef>,
}

impl UserClient {
	/// Upper bound on rebuild-and-republish attempts after a successor
	/// conflict, matching the reference client's `send` retry ceiling.
	const MAX_REBUILD_RETRIES: u32 = 2;

	/// Bind `client` to `signer` (the originator and fee payer for writes;
	/// `None` for a read-only client).
	pub fn from_parts(client: KeetaClient, signer: Option<AccountRef>) -> Self {
		Self { client, account: None, signer }
	}

	/// Set a distinct operating account, used for reads and as the block
	/// originator for writes while `signer` still signs.
	#[must_use]
	pub fn with_account(mut self, account: AccountRef) -> Self {
		self.account = Some(account);
		self
	}

	/// Bind a client for a well-known [`Network`] to `signer` (or `None` for a
	/// read-only client), using the network's default representatives.
	///
	/// # Errors
	///
	/// - [`ClientError::Account`] -- a representative key in the network
	///   registry fails to parse.
	#[cfg(feature = "http")]
	pub fn from_network(network: Network, signer: Option<AccountRef>) -> Result<Self, ClientError> {
		let client = KeetaClient::try_from(network)?;
		Ok(Self::from_parts(client, signer))
	}

	/// Bind a client targeting a single representative reachable at `hostname`
	/// (TLS when `ssl`), stamping `network_id` onto originated blocks.
	#[cfg(feature = "http")]
	pub fn from_single_rep(
		hostname: impl AsRef<str>,
		ssl: bool,
		rep_key: &AccountRef,
		network_id: impl Into<BigInt>,
		signer: Option<AccountRef>,
	) -> Self {
		let scheme = match ssl {
			true => "https",
			false => "http",
		};

		let api_url = alloc::format!("{scheme}://{}/api", hostname.as_ref());
		let rep = RepEndpoint::new(api_url, Arc::clone(rep_key), 1u8);
		let client = KeetaClient::with_representatives([rep], ClientConfig::default()).with_network(network_id);
		Self::from_parts(client, signer)
	}

	/// The underlying transport client.
	pub fn client(&self) -> &KeetaClient {
		&self.client
	}

	/// The operating account this client reads from and originates writes for.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- neither an operating account nor a
	///   signer is bound.
	pub fn account(&self) -> Result<AccountRef, ClientError> {
		self.account_or(None)
	}

	/// The bound signer, if any.
	pub fn signer_account(&self) -> Option<&AccountRef> {
		self.signer.as_ref()
	}

	/// Whether this client has no signer and therefore rejects writes.
	pub fn is_read_only(&self) -> bool {
		self.signer.is_none()
	}

	/// The operating account: `override`, then the configured account, then
	/// the signer; [`ClientError::SignerRequired`] when none is bound.
	fn account_or(&self, account: Option<&AccountRef>) -> Result<AccountRef, ClientError> {
		if let Some(account) = account {
			return Ok(Arc::clone(account));
		}
		if let Some(account) = &self.account {
			return Ok(Arc::clone(account));
		}
		if let Some(signer) = &self.signer {
			return Ok(Arc::clone(signer));
		}

		Err(ClientError::SignerRequired)
	}

	/// The bound signer, or [`ClientError::SignerRequired`].
	fn signer(&self) -> Result<AccountRef, ClientError> {
		match &self.signer {
			Some(signer) => Ok(Arc::clone(signer)),
			None => Err(ClientError::SignerRequired),
		}
	}

	/// A builder for the operating account, signed by the bound signer. Writes
	/// require a signer, so this errors when none is provided.
	fn signed_builder(&self) -> Result<TransactionBuilder, ClientError> {
		let signer = self.signer()?;
		let account = self.account_or(None)?;
		let mut builder = self.client.builder(&account);
		if account.to_string() != signer.to_string() {
			builder.for_account_with_signer(&account, &signer);
		}

		Ok(builder)
	}

	/// The settled balance of `token` held by the operating account.
	pub async fn balance(&self, token: impl AccountPublicKey) -> Result<Amount, ClientError> {
		let account = self.account_or(None)?;
		self.client.balance(&*account, token).await
	}

	/// Every token balance held by the operating account.
	pub async fn all_balances(&self) -> Result<Vec<TokenBalance>, ClientError> {
		let account = self.account_or(None)?;
		self.client.balances(&*account).await
	}

	/// The full state of the operating account.
	pub async fn state(&self) -> Result<AccountState, ClientError> {
		let account = self.account_or(None)?;
		self.client.state(&*account).await
	}

	/// The operating account's head block, if any.
	pub async fn head(&self) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.head_block(&*account).await
	}

	/// The operating account's settled chain (first/default page).
	pub async fn chain(&self) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain(&*account).await
	}

	/// A single page of the operating account's chain, bounded by `query`.
	pub async fn chain_page(&self, query: ChainQuery) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain_page(&*account, query).await
	}

	/// Every block in the operating account's chain, following the node's
	/// pagination cursor with `page_limit` blocks per request.
	pub async fn chain_all(&self, page_limit: u32) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain_all(&*account, page_limit).await
	}

	/// The operating account's transaction history (first/default page).
	pub async fn history(&self) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = self.account_or(None)?;
		self.client.history(&*account).await
	}

	/// Every entry in the operating account's history, fetched by following
	/// the node's cursor with `page_limit` per request.
	pub async fn history_all(&self, page_limit: u32) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = self.account_or(None)?;
		self.client.history_all(&*account, page_limit).await
	}

	/// A single page of the operating account's history, bounded by `query`.
	pub async fn history_page(&self, query: HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = self.account_or(None)?;
		self.client.history_page(&*account, query).await
	}

	/// The operating account's half-published successor, if any reps agree on
	/// one.
	pub async fn pending_block(&self) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.pending_block(&*account).await
	}

	/// Recover the operating account's half-published staple, optionally
	/// republishing it. Any required fee block is paid by the bound signer
	/// when one is present.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- neither an operating account nor a
	///   signer is bound.
	/// - [`ClientError::Node`] -- recovery failed at the node.
	pub async fn recover(&self, publish: bool) -> Result<Option<VoteStaple>, ClientError> {
		let account = self.account_or(None)?;
		let mut options = TransmitOptions::default();
		if let Some(signer) = &self.signer {
			options = options.with_fee_signer(signer);
		}

		self.client
			.recover_account(&account, publish, options)
			.await
	}

	/// Sync the operating account across lagging representatives, optionally
	/// republishing the missing staple.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- neither an operating account nor a
	///   signer is bound.
	/// - [`ClientError::Node`] -- the sync failed at the node.
	pub async fn sync(&self, publish: bool) -> Result<Option<VoteStaple>, ClientError> {
		let account = self.account_or(None)?;
		self.client.sync_account(&account, publish).await
	}

	/// The access-control entries the operating account grants as principal.
	pub async fn acls(&self) -> Result<Vec<Acl>, ClientError> {
		let account = self.account_or(None)?;
		self.client.acls_by_principal(&*account).await
	}

	/// The access-control entries naming the operating account as entity.
	pub async fn acls_by_entity(&self) -> Result<Vec<Acl>, ClientError> {
		let account = self.account_or(None)?;
		self.client.acls_by_entity(&*account).await
	}

	/// The access-control entries the operating account grants as principal,
	/// each enriched with the target's info (opaque JSON; std-only).
	#[cfg(feature = "std")]
	pub async fn acls_with_info(&self) -> Result<serde_json::Value, ClientError> {
		let account = self.account_or(None)?;
		self.client.acls_by_principal_with_info(&*account).await
	}

	/// A specific block by hash, regardless of account. `side` selects the
	/// ledger to read (`None` defaults to the main ledger).
	pub async fn block(&self, blockhash: BlockHash, side: Option<LedgerSide>) -> Result<Option<Block>, ClientError> {
		self.client.block(blockhash, side).await
	}

	/// The operating account's block carrying the idempotency `key`, if any,
	/// searching the given `side` (`None` defaults to the main ledger).
	pub async fn block_from_idempotent(
		&self,
		key: impl AsRef<str>,
		side: Option<LedgerSide>,
	) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.block_by_idempotent(&*account, key, side).await
	}

	/// Vote quotes for `blocks` from every responding representative.
	pub async fn quotes(&self, blocks: &[Block]) -> Result<Vec<VoteQuote>, ClientError> {
		self.client.quotes(blocks).await
	}

	/// The operations in `staples` that involve `account`, keyed by staple id
	/// and ordered as published: every operation of a block the account
	/// produced, plus operations on other accounts' blocks that name it.
	pub fn filter_staple_operations(
		staples: &[VoteStaple],
		account: impl AccountPublicKey,
	) -> BTreeMap<VoteBlockHash, Vec<BlockEffects>> {
		staples
			.iter()
			.map(|staple| {
				let blocks = staple
					.blocks()
					.iter()
					.map(|block| block_effects(block, &account));
				(staple.block_hash(), blocks.collect())
			})
			.collect()
	}

	/// [`Self::filter_staple_operations`] over the operating account.
	pub fn staple_effects(
		&self,
		staples: &[VoteStaple],
	) -> Result<BTreeMap<VoteBlockHash, Vec<BlockEffects>>, ClientError> {
		let account = self.account_or(None)?;
		Ok(Self::filter_staple_operations(staples, &*account))
	}

	/// The certificates attached to the operating account.
	pub async fn certificates(&self) -> Result<Vec<Certificate>, ClientError> {
		let account = self.account_or(None)?;
		self.client.certificates(&*account).await
	}

	/// A single certificate on the operating account by its `hash`, if present.
	pub async fn certificate(&self, hash: [u8; 32]) -> Result<Option<Certificate>, ClientError> {
		let account = self.account_or(None)?;
		self.client.certificate(&*account, hash).await
	}

	/// Start a transaction originated by the operating account and signed by
	/// the bound signer.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	pub fn init_builder(&self) -> Result<TransactionBuilder, ClientError> {
		self.signed_builder()
	}

	/// Publish a single block, paying any required fee with the bound signer.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::FeeRequired`] -- a required fee cannot be paid.
	/// - [`ClientError::Node`] -- the node rejected the staple.
	pub async fn publish(&self, block: Block, options: TransmitOptions) -> Result<bool, ClientError> {
		self.client
			.publish(block, self.or_default_fee_payer(options)?)
			.await
	}

	/// Transmit an assembled multi-block staple, paying any required fee with
	/// the bound signer.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::FeeRequired`] -- a required fee cannot be paid.
	/// - [`ClientError::Node`] -- the node rejected the staple.
	pub async fn transmit(&self, blocks: &[Block], options: TransmitOptions) -> Result<bool, ClientError> {
		self.client
			.transmit(blocks, self.or_default_fee_payer(options)?)
			.await
	}

	/// Send `amount` of `token` from the operating account to `to`.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::FeeRequired`] -- a required fee cannot be paid.
	/// - [`ClientError::Node`] -- the node rejected the staple.
	pub async fn send(&self, to: &AccountRef, token: &AccountRef, amount: Amount) -> Result<bool, ClientError> {
		self.build_and_publish(move |builder| {
			builder.send(to, token, amount.clone());
		})
		.await
	}

	/// Send `amount` of `token` to `to`, attaching `external` reference data.
	/// External sends are never aggregated with other sends.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::FeeRequired`] -- a required fee cannot be paid.
	/// - [`ClientError::Node`] -- the node rejected the staple.
	pub async fn send_external(
		&self,
		to: &AccountRef,
		token: &AccountRef,
		amount: Amount,
		external: impl Into<String>,
	) -> Result<bool, ClientError> {
		let external = external.into();
		self.build_and_publish(move |builder| {
			builder.send_external(to, token, amount.clone(), external.clone());
		})
		.await
	}

	/// Set the operating account's representative to `rep`.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the block.
	pub async fn set_rep(&self, rep: &AccountRef) -> Result<bool, ClientError> {
		let rep = Arc::clone(rep);
		self.build_and_publish(move |builder| {
			builder.set_rep(&rep);
		})
		.await
	}

	/// Set the operating account's on-chain info.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the block.
	pub async fn set_info(&self, info: SetInfo) -> Result<bool, ClientError> {
		self.build_and_publish(move |builder| {
			builder.set_info(info.clone());
		})
		.await
	}

	/// Modify the permissions the operating account grants.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the block.
	pub async fn update_permissions(&self, permissions: ModifyPermissions) -> Result<bool, ClientError> {
		self.build_and_publish(move |builder| {
			builder.modify_permissions(permissions.clone());
		})
		.await
	}

	/// Add or remove a certificate on the operating account.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the block.
	pub async fn modify_certificate(&self, certificate: ManageCertificate) -> Result<bool, ClientError> {
		self.build_and_publish(move |builder| {
			builder.manage_certificate(certificate.clone());
		})
		.await
	}

	/// Adjust `token`'s supply and, in the same transaction, `holder`'s balance
	/// of it, both signed by the bound signer.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the block.
	pub async fn modify_token_supply_and_balance(
		&self,
		token: &AccountRef,
		holder: Option<&AccountRef>,
		amount: Amount,
		method: AdjustMethod,
	) -> Result<bool, ClientError> {
		let signer = self.signer()?;
		let token = Arc::clone(token);
		let holder = match holder {
			Some(holder) => Arc::clone(holder),
			None => self.account_or(None)?,
		};

		let distinct_holder = holder.to_string() != token.to_string();
		// A burn must debit the holder's balance before cutting supply
		let burn = matches!(method, AdjustMethod::Subtract);
		self.build_and_publish(move |builder| {
			if burn {
				builder.for_account_with_signer(&holder, &signer);
				builder.modify_token_balance(&token, amount.clone(), method);
				if distinct_holder {
					builder.for_account_with_signer(&token, &signer);
				}

				builder.modify_token_supply(amount.clone(), method);
			} else {
				builder.for_account_with_signer(&token, &signer);
				builder.modify_token_supply(amount.clone(), method);
				if distinct_holder {
					builder.for_account_with_signer(&holder, &signer);
				}

				builder.modify_token_balance(&token, amount.clone(), method);
			}
		})
		.await
	}

	/// Create an identifier of `key_type` under the operating account and
	/// publish the creating block, returning the derived address.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::Node`] -- the node rejected the creating block.
	pub async fn generate_identifier(
		&self,
		key_type: KeyPairType,
		create_arguments: Option<IdentifierCreateArguments>,
	) -> Result<AccountRef, ClientError> {
		let mut builder = self.signed_builder()?;
		let pending = builder.generate_identifier(key_type, create_arguments);
		let blocks = builder.build().await?;

		self.originate(blocks).await?;
		pending.get()
	}

	/// Bootstrap a brand-new network: the bound signer (acting as the initial
	/// trusted account) seals the network-address and base-token blocks, mints
	/// `add_supply_amount` to the operating account, delegates that account's
	/// voting weight, and transmits the resulting permanent genesis staple.
	///
	/// Returns whether the staple was accepted by the network.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::NoRepresentatives`] -- no delegate is given and the
	///   client has no representative to default to.
	/// - [`ClientError::Block`] / [`ClientError::Vote`] -- the genesis staple
	///   cannot be built.
	pub async fn initialize_network(&self, options: InitializeNetwork) -> Result<bool, ClientError> {
		let trusted = self.signer()?;
		let recipient = self.account_or(None)?;
		let delegate_to = match &options.delegate_to {
			Some(delegate) => Arc::clone(delegate),
			None => self
				.client
				.first_rep_account()?
				.ok_or(ClientError::NoRepresentatives)?,
		};

		let staple = generate_initial_vote_staple(&self.client, &trusted, &recipient, &delegate_to, &options)?;
		self.client.transmit_staple(&staple).await
	}

	/// Build a swap-request block: send `send_token`/`send_amount` to the
	/// counterparty and receive `receive_token`/`receive_amount` from it, in a
	/// single block. The block is unpublished for the counterparty to accept.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::SwapMultiBlock`] -- the request does not render to a
	///   single block.
	pub async fn create_swap_request(&self, request: CreateSwapRequest) -> Result<Block, ClientError> {
		let mut builder = self.signed_builder()?;
		builder.send(&request.counterparty, &request.send_token, request.send_amount);
		builder.receive_with(
			&request.counterparty,
			&request.receive_token,
			request.receive_amount,
			request.receive_exact,
			None,
		);

		let mut blocks = builder.build().await?;
		match blocks.len() {
			1 => Ok(blocks.remove(0)),
			_ => Err(ClientError::SwapMultiBlock),
		}
	}

	/// Accept a maker's swap request, returning the taker's matching block(s)
	/// followed by the maker's block. Transmit the returned slice together so
	/// the swap settles atomically.
	///
	/// # Errors
	///
	/// - [`ClientError::SignerRequired`] -- no signer is bound.
	/// - [`ClientError::SwapMissingSend`] / [`ClientError::SwapMissingReceive`]
	///   -- the request block lacks a swap leg.
	/// - [`ClientError::SwapAccountMismatch`] -- the legs do not name this account.
	/// - [`ClientError::SwapTokenMismatch`] / [`ClientError::SwapAmountMismatch`]
	///   / [`ClientError::SwapAmountTooLow`] / [`ClientError::SwapExactMismatch`]
	///   -- an [`SwapExpectation`](crate::SwapExpectation) is not met.
	pub async fn accept_swap_request(&self, request: AcceptSwapRequest) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		let (send, receive) = swap_legs(&request.block)?;

		if send.to.to_string() != receive.from.to_string() {
			return Err(ClientError::SwapAccountMismatch);
		}
		if send.to.to_string() != account.to_string() {
			return Err(ClientError::SwapAccountMismatch);
		}

		let send_amount: Amount = resolve_swap_amount(send, receive, request.expected.as_ref())?;

		let maker = request.block.data().account();
		let mut builder = self.signed_builder()?;
		builder.send(maker, &receive.token, send_amount);

		let mut blocks = builder.build().await?;
		blocks.push(request.block);
		Ok(blocks)
	}

	/// Keep the caller's fee-block factory when supplied, otherwise fall back
	/// to the bound signer paying for itself.
	fn or_default_fee_payer(&self, options: TransmitOptions) -> Result<TransmitOptions, ClientError> {
		if options.generate_fee_block.is_some() {
			return Ok(options);
		}

		let signer = self.signer()?;
		Ok(options.with_fee_signer(&signer))
	}

	/// Build the operating account's block(s) from `assemble`, then publish.
	///
	/// On a `LEDGER_SUCCESSOR_VOTE_EXISTS` conflict (another block already
	/// claimed the head height), recover the operating account and, if a
	/// staple was reassembled, re-render the operations against the advanced
	/// head and republish. `assemble` can be invoked multiple times, so it must
	/// not consume its captured operands.
	async fn build_and_publish(&self, assemble: impl Fn(&mut TransactionBuilder)) -> Result<bool, ClientError> {
		let mut attempt = 0u32;
		loop {
			let mut builder = self.signed_builder()?;
			assemble(&mut builder);
			let blocks = builder.build().await?;

			match self.originate(blocks).await {
				Ok(accepted) => return Ok(accepted),
				Err(error) => {
					let conflict = is_ledger_code(&error, "LEDGER_SUCCESSOR_VOTE_EXISTS");
					if !conflict || attempt >= Self::MAX_REBUILD_RETRIES {
						return Err(error);
					}

					// Recovering only helps once it reassembles the conflicting
					// staple; with nothing to recover the conflict is terminal.
					match self.recover(true).await? {
						Some(_) => attempt += 1,
						None => return Err(error),
					}
				}
			}
		}
	}

	/// Publish each block, paying any required fee with the bound signer.
	/// Acceptance is the conjunction of every block's result; a rejection
	/// stops the run.
	async fn originate(&self, blocks: Vec<Block>) -> Result<bool, ClientError> {
		let signer = self.signer()?;
		let options = TransmitOptions::default().with_fee_signer(&signer);
		let mut accepted = true;
		for block in blocks {
			accepted &= self.client.publish(block, options.clone()).await?;
			if !accepted {
				break;
			}
		}

		Ok(accepted)
	}
}

/// The [`BlockEffects`] of one staple block for `account`: every operation
/// when the account produced the block, otherwise only the operations that
/// name it.
fn block_effects(block: &Block, account: &impl AccountPublicKey) -> BlockEffects {
	let operations = block.data().operations().iter().enumerate();
	let operation_indexes = match same_account(block.data().account(), account) {
		true => operations.map(|(index, _)| index).collect(),
		false => operations
			.filter(|(_, operation)| operation_involves(operation, account))
			.map(|(index, _)| index)
			.collect(),
	};

	BlockEffects { block: block.clone(), operation_indexes }
}

/// Whether `operation` names `account` as a participant: send/set-rep
/// recipient, modify-permissions account principal, create-identifier
/// identifier, or receive source/forward. Info, token-admin, and certificate
/// operations reference no account directly.
fn operation_involves(operation: &Operation, account: &impl AccountPublicKey) -> bool {
	match operation {
		Operation::Send(send) => same_account(&send.to, account),
		Operation::SetRep(set_rep) => same_account(&set_rep.to, account),
		Operation::ModifyPermissions(change) => {
			matches!(&change.principal, ModifyPermissionsPrincipal::Account(principal) if same_account(principal, account))
		}
		Operation::CreateIdentifier(create) => same_account(&create.identifier, account),
		Operation::Receive(receive) => {
			same_account(&receive.from, account)
				|| receive
					.forward
					.as_ref()
					.is_some_and(|forward| same_account(forward, account))
		}
		Operation::SetInfo(_)
		| Operation::TokenAdminSupply(_)
		| Operation::TokenAdminModifyBalance(_)
		| Operation::ManageCertificate(_) => false,
	}
}

/// Whether two accounts share the same public-key identity (algorithm plus
/// raw key bytes).
fn same_account(candidate: &AccountRef, account: &impl AccountPublicKey) -> bool {
	candidate.to_keypair_type() == account.to_keypair_type()
		&& candidate.as_public_key_bytes() == account.as_public_key_bytes()
}

/// Extract the SEND and RECEIVE operations from a swap-request block.
fn swap_legs(block: &Block) -> Result<(&Send, &Receive), ClientError> {
	let mut send = None;
	let mut receive = None;
	for operation in block.data().operations() {
		match operation {
			Operation::Send(value) => send = Some(value),
			Operation::Receive(value) => receive = Some(value),
			_ => {}
		}
	}

	let send = send.ok_or(ClientError::SwapMissingSend)?;
	let receive = receive.ok_or(ClientError::SwapMissingReceive)?;
	Ok((send, receive))
}

/// Determine the taker's send amount, defaulting to the maker's requested
/// receive amount and applying any [`SwapExpectation`](crate::SwapExpectation)
/// assertions.
fn resolve_swap_amount(
	send: &Send,
	receive: &Receive,
	expected: Option<&crate::swap::SwapExpectation>,
) -> Result<Amount, ClientError> {
	let mut send_amount = receive.amount.clone();
	let Some(expected) = expected else {
		return Ok(send_amount);
	};

	if let Some(expected_receive) = &expected.receive {
		assert_swap_token(&send.token, expected_receive)?;
		assert_swap_amount(&send.amount, expected_receive)?;
	}

	if let Some(expected_send) = &expected.send {
		assert_swap_token(&receive.token, expected_send)?;
		if let Some(amount) = &expected_send.amount {
			if *amount < receive.amount {
				return Err(ClientError::SwapAmountTooLow);
			}
			if receive.exact && receive.amount != *amount {
				return Err(ClientError::SwapExactMismatch);
			}
			send_amount = amount.clone();
		}
	}

	Ok(send_amount)
}

/// Assert an operation's `token` matches the expected token, when one is set.
fn assert_swap_token(token: &AccountRef, expected: &SwapTokenAmount) -> Result<(), ClientError> {
	if let Some(wanted) = &expected.token {
		if token.to_string() != wanted.to_string() {
			return Err(ClientError::SwapTokenMismatch);
		}
	}

	Ok(())
}

/// Assert an operation's `amount` matches the expected amount, when one is set.
fn assert_swap_amount(amount: &Amount, expected: &SwapTokenAmount) -> Result<(), ClientError> {
	if let Some(wanted) = &expected.amount {
		if amount != wanted {
			return Err(ClientError::SwapAmountMismatch);
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use keetanetwork_block::testing::{generate_ed25519_ref, generate_identifier_ref};

	use core::mem::discriminant;

	use super::*;
	use crate::swap::SwapExpectation;

	/// Fixed send leg every case resolves against: 100 of token 3 to account 1.
	fn send_op(amount: u64) -> Send {
		Send {
			to: generate_ed25519_ref(1),
			amount: Amount::from(amount),
			token: generate_ed25519_ref(3),
			external: None,
		}
	}

	/// Fixed receive leg every case resolves against: 50 of token 4 from
	/// account 1, exactness varied per scenario.
	fn receive_op(amount: u64, exact: bool) -> Receive {
		Receive {
			amount: Amount::from(amount),
			token: generate_ed25519_ref(4),
			from: generate_ed25519_ref(1),
			exact,
			forward: None,
		}
	}

	/// A send-side expectation overriding only the send amount.
	fn send_expectation(amount: u64) -> SwapExpectation {
		SwapExpectation {
			receive: None,
			send: Some(SwapTokenAmount { token: None, amount: Some(Amount::from(amount)) }),
		}
	}

	/// Resolve the fixed legs against `expectation` and require `expected`.
	fn assert_resolves_to(expectation: Option<SwapExpectation>, exact: bool, expected: u64) {
		let resolved = resolve_swap_amount(&send_op(100), &receive_op(50, exact), expectation.as_ref());
		assert_eq!(resolved.ok(), Some(Amount::from(expected)));
	}

	/// Resolve the fixed legs against `expectation` and require the `expected`
	/// rejection variant.
	fn assert_rejects(expectation: SwapExpectation, exact: bool, expected: ClientError) {
		let resolved = resolve_swap_amount(&send_op(100), &receive_op(50, exact), Some(&expectation));
		assert_eq!(resolved.err().map(|error| discriminant(&error)), Some(discriminant(&expected)));
	}

	#[test]
	fn swap_amount_defaults_to_requested_receive() {
		assert_resolves_to(None, false, 50);
	}

	#[test]
	fn swap_raises_send_amount_when_permitted() {
		assert_resolves_to(Some(send_expectation(70)), false, 70);
	}

	#[test]
	fn swap_rejects_send_amount_below_requested() {
		assert_rejects(send_expectation(49), false, ClientError::SwapAmountTooLow);
	}

	#[test]
	fn swap_rejects_inexact_override_of_exact_receive() {
		assert_rejects(send_expectation(60), true, ClientError::SwapExactMismatch);
	}

	#[test]
	fn swap_rejects_mismatched_receive_token() {
		let expectation = SwapExpectation {
			receive: Some(SwapTokenAmount { token: Some(generate_ed25519_ref(9)), amount: None }),
			send: None,
		};
		assert_rejects(expectation, false, ClientError::SwapTokenMismatch);
	}

	#[test]
	fn swap_rejects_mismatched_receive_amount() {
		let expectation = SwapExpectation {
			receive: Some(SwapTokenAmount { token: None, amount: Some(Amount::from(99u64)) }),
			send: None,
		};
		assert_rejects(expectation, false, ClientError::SwapAmountMismatch);
	}

	type BlockResult = Result<(), Box<dyn core::error::Error>>;

	/// A send from the producing account 1 to `recipient`.
	fn send_to(recipient: u8) -> Operation {
		Operation::Send(Send {
			to: generate_ed25519_ref(recipient),
			amount: Amount::from(10u64),
			token: generate_identifier_ref(1, KeyPairType::TOKEN, 0),
			external: None,
		})
	}

	/// A SET_INFO carrying no account references, so it never matches a
	/// foreign filter.
	fn set_info() -> Operation {
		Operation::SetInfo(SetInfo {
			name: String::new(),
			description: String::new(),
			metadata: String::new(),
			default_permission: None,
		})
	}

	/// A signed opening block for account 1 carrying `operations`.
	fn effects_block(operations: Vec<Operation>) -> Result<Block, Box<dyn core::error::Error>> {
		let mut builder = keetanetwork_block::BlockBuilder::default()
			.with_network(0u8)
			.with_account(generate_ed25519_ref(1))
			.as_opening();
		for operation in operations {
			builder = builder.with_operation(operation);
		}

		Ok(builder.build()?.sign()?)
	}

	#[test]
	fn producer_blocks_keep_every_operation() -> BlockResult {
		let block = effects_block(vec![send_to(2), set_info()])?;

		let effects = block_effects(&block, &*generate_ed25519_ref(1));
		assert_eq!(effects.operation_indexes, vec![0, 1]);
		Ok(())
	}

	#[test]
	fn foreign_blocks_drop_operations_not_naming_the_account() -> BlockResult {
		let block = effects_block(vec![send_to(2), set_info()])?;

		let effects = block_effects(&block, &*generate_ed25519_ref(9));
		assert!(effects.operation_indexes.is_empty());
		Ok(())
	}

	#[test]
	fn send_recipients_see_only_the_send_operation() -> BlockResult {
		let block = effects_block(vec![set_info(), send_to(2)])?;

		let effects = block_effects(&block, &*generate_ed25519_ref(2));
		assert_eq!(effects.operation_indexes, vec![1]);
		assert!(matches!(effects.operations().next(), Some(Operation::Send(_))));
		Ok(())
	}

	#[test]
	fn receive_forwards_see_the_receive_operation() -> BlockResult {
		let forward = generate_ed25519_ref(7);
		let receive = Receive {
			amount: Amount::from(5u64),
			token: generate_identifier_ref(1, KeyPairType::TOKEN, 0),
			from: generate_ed25519_ref(2),
			exact: true,
			forward: Some(Arc::clone(&forward)),
		};
		let block = effects_block(vec![Operation::Receive(receive)])?;

		let effects = block_effects(&block, &*forward);
		assert_eq!(effects.operation_indexes, vec![0]);
		assert!(matches!(effects.operations().next(), Some(Operation::Receive(_))));
		Ok(())
	}
}
