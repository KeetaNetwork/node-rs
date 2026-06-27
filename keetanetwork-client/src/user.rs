//! Signer-bound high-level facade over [`KeetaClient`].

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{
	AccountRef, AdjustMethod, Amount, Block, IdentifierCreateArguments, ManageCertificate, ModifyPermissions,
	Operation, Receive, Send, SetInfo,
};
use keetanetwork_vote::{VoteQuote, VoteStaple};

use crate::builder::TransactionBuilder;
use crate::client::{is_ledger_code, KeetaClient};
use crate::error::ClientError;
use crate::model::{
	AccountState, Acl, Certificate, ChainQuery, HistoryEntry, HistoryQuery, TokenBalance, TransmitOptions,
};
use crate::swap::{AcceptSwapRequest, CreateSwapRequest, SwapTokenAmount};
use crate::transport::LedgerSide;

#[cfg(feature = "http")]
use {crate::config::ClientConfig, crate::network::Network, crate::rep::RepEndpoint, num_bigint::BigInt};

#[cfg(feature = "std")]
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
	pub async fn balance(&self, token: impl AsRef<str>) -> Result<Amount, ClientError> {
		let account = self.account_or(None)?;
		self.client.balance(account.to_string(), token).await
	}

	/// Every token balance held by the operating account.
	pub async fn all_balances(&self) -> Result<Vec<TokenBalance>, ClientError> {
		let account = self.account_or(None)?;
		self.client.balances(account.to_string()).await
	}

	/// The full state of the operating account.
	pub async fn state(&self) -> Result<AccountState, ClientError> {
		let account = self.account_or(None)?;
		self.client.state(account.to_string()).await
	}

	/// The operating account's head block, if any.
	pub async fn head(&self) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.head_block(account.to_string()).await
	}

	/// The operating account's settled chain (first/default page).
	pub async fn chain(&self) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain(account.to_string()).await
	}

	/// A single page of the operating account's chain, bounded by `query`.
	pub async fn chain_page(&self, query: ChainQuery) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain_page(account.to_string(), query).await
	}

	/// Every block in the operating account's chain, following the node's
	/// pagination cursor with `page_limit` blocks per request.
	pub async fn chain_all(&self, page_limit: u32) -> Result<Vec<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.chain_all(account.to_string(), page_limit).await
	}

	/// The operating account's transaction history (first/default page).
	pub async fn history(&self) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = self.account_or(None)?;
		self.client.history(account.to_string()).await
	}

	/// A single page of the operating account's history, bounded by `query`.
	pub async fn history_page(&self, query: HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		let account = self.account_or(None)?;
		self.client.history_page(account.to_string(), query).await
	}

	/// The operating account's half-published successor, if any reps agree on
	/// one.
	pub async fn pending_block(&self) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client.pending_block(account.to_string()).await
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
		let options = TransmitOptions { fee_signer: self.signer.clone(), ..Default::default() };
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
		self.client.acls_by_principal(account.to_string()).await
	}

	/// The access-control entries naming the operating account as entity.
	pub async fn acls_by_entity(&self) -> Result<Vec<Acl>, ClientError> {
		let account = self.account_or(None)?;
		self.client.acls_by_entity(account.to_string()).await
	}

	/// The access-control entries the operating account grants as principal,
	/// each enriched with the target's info (opaque JSON; std-only).
	#[cfg(feature = "std")]
	pub async fn acls_with_info(&self) -> Result<serde_json::Value, ClientError> {
		let account = self.account_or(None)?;
		self.client
			.acls_by_principal_with_info(account.to_string())
			.await
	}

	/// A specific block by hash, regardless of account. `side` selects the
	/// ledger to read (`None` defaults to the main ledger).
	pub async fn block(
		&self,
		blockhash: impl AsRef<str>,
		side: Option<LedgerSide>,
	) -> Result<Option<Block>, ClientError> {
		self.client.block(blockhash, side).await
	}

	/// The operating account's block carrying the idempotency `key`, if any.
	pub async fn block_from_idempotent(&self, key: impl AsRef<str>) -> Result<Option<Block>, ClientError> {
		let account = self.account_or(None)?;
		self.client
			.block_by_idempotent(account.to_string(), key)
			.await
	}

	/// Vote quotes for `blocks` from every responding representative.
	pub async fn quotes(&self, blocks: &[Block]) -> Result<Vec<VoteQuote>, ClientError> {
		self.client.quotes(blocks).await
	}

	/// The certificates attached to the operating account.
	pub async fn certificates(&self) -> Result<Vec<Certificate>, ClientError> {
		let account = self.account_or(None)?;
		self.client.certificates(account.to_string()).await
	}

	/// A single certificate on the operating account by its `hash`, if present.
	pub async fn certificate(&self, hash: impl AsRef<str>) -> Result<Option<Certificate>, ClientError> {
		let account = self.account_or(None)?;
		self.client.certificate(account.to_string(), hash).await
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
			.publish(block, self.with_fee_signer(options)?)
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
			.transmit(blocks, self.with_fee_signer(options)?)
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
	#[cfg(feature = "std")]
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

	/// Default the fee signer to the bound signer when the caller left it
	/// unset.
	fn with_fee_signer(&self, mut options: TransmitOptions) -> Result<TransmitOptions, ClientError> {
		if options.fee_signer.is_none() {
			options.fee_signer = Some(self.signer()?);
		}

		Ok(options)
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
		let options = TransmitOptions { fee_signer: Some(signer), ..Default::default() };
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
	use keetanetwork_block::testing::generate_ed25519_ref;

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
}
