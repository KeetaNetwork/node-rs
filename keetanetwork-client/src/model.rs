//! Domain-typed request/response models exposed by [`KeetaClient`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;

use keetanetwork_block::{AccountRef, Amount, Block, BlockHash, BlockTime, Operation, Permissions};
use keetanetwork_vote::{VoteBlockHash, VoteQuote, VoteStaple};

use crate::client::KeetaClient;
use crate::error::ClientError;
use crate::sync::Once;

/// A handle to an identifier account that does not exist until the
/// [`TransactionBuilder`](crate::TransactionBuilder) that creates it is built.
#[derive(Clone, Debug, Default)]
pub struct PendingAccount {
	cell: Arc<Once<AccountRef>>,
}

impl PendingAccount {
	/// Resolve the derived identifier address, or
	/// [`ClientError::UnresolvedIdentifier`] when the builder has not yet
	/// produced the creating block.
	pub fn get(&self) -> Result<AccountRef, ClientError> {
		self.cell
			.get()
			.map(Arc::clone)
			.ok_or(ClientError::UnresolvedIdentifier)
	}

	/// Fill the address once, during `build`. A second fill is ignored,
	/// preserving the set-once invariant.
	pub(crate) fn fill(&self, account: AccountRef) {
		self.cell.call_once(|| account);
	}
}

/// An operation operand that is either a resolved account or a
/// [`PendingAccount`] resolved at build time.
///
/// Builder operands accept `impl Into<AccountOrPending>`, so a resolved
/// [`AccountRef`] and a builder-issued [`PendingAccount`] are both usable
/// without separate methods.
#[derive(Clone, Debug)]
pub enum AccountOrPending {
	/// An already-known account.
	Resolved(AccountRef),
	/// An identifier resolved when the builder is built.
	Pending(PendingAccount),
}

impl AccountOrPending {
	/// Resolve to a concrete account, or [`ClientError::UnresolvedIdentifier`]
	/// when a pending identifier has not been filled.
	pub(crate) fn resolve(&self) -> Result<AccountRef, ClientError> {
		match self {
			AccountOrPending::Resolved(account) => Ok(Arc::clone(account)),
			AccountOrPending::Pending(pending) => pending.get(),
		}
	}
}

impl From<AccountRef> for AccountOrPending {
	fn from(account: AccountRef) -> Self {
		AccountOrPending::Resolved(account)
	}
}

impl From<&AccountRef> for AccountOrPending {
	fn from(account: &AccountRef) -> Self {
		AccountOrPending::Resolved(Arc::clone(account))
	}
}

impl From<PendingAccount> for AccountOrPending {
	fn from(pending: PendingAccount) -> Self {
		AccountOrPending::Pending(pending)
	}
}

impl From<&PendingAccount> for AccountOrPending {
	fn from(pending: &PendingAccount) -> Self {
		AccountOrPending::Pending(pending.clone())
	}
}

/// A token balance entry for an account.
#[derive(Debug, Clone)]
pub struct TokenBalance {
	/// Token account.
	pub token: AccountRef,
	/// Settled balance.
	pub balance: Amount,
}

/// A representative and its voting weight.
#[derive(Debug, Clone)]
pub struct Representative {
	/// Representative account.
	pub account: AccountRef,
	/// Voting weight.
	pub weight: Amount,
	/// REST API base URL the representative can be reached at, when the node
	/// advertises it (the plural `representatives` endpoint includes this; the
	/// singular lookup does not).
	pub api_url: Option<String>,
}

/// A point-in-time ledger checksum.
#[derive(Debug, Clone)]
pub struct LedgerChecksum {
	/// XOR checksum of the ledger.
	pub checksum: Amount,
	/// Approximate moment the checksum was taken.
	pub moment: Option<BlockTime>,
	/// Half the measurement window, in milliseconds.
	pub moment_range: Option<f64>,
}

/// A history entry: a verified vote staple with its id and timestamp.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
	/// The verified vote staple.
	pub staple: VoteStaple,
	/// The staple's id: the hash of the block hashes it covers.
	pub id: Option<VoteBlockHash>,
	/// The moment the staple was committed.
	pub timestamp: Option<BlockTime>,
}

/// One staple block together with the subset of its operations that involve
/// a filtered account (see
/// [`UserClient::filter_staple_operations`](crate::UserClient::filter_staple_operations)).
///
/// Operations are carried as indexes into the block's operation list, so the
/// selection survives any boundary the block itself crosses.
#[derive(Debug, Clone)]
pub struct BlockEffects {
	/// The block the operations came from.
	pub block: Block,
	/// Indexes into the block's operation list for the operations involving
	/// the filtered account, in block order.
	pub operation_indexes: Vec<usize>,
}

impl BlockEffects {
	/// The operations involving the filtered account, resolved against the block.
	pub fn operations(&self) -> impl Iterator<Item = &Operation> {
		let operations = self.block.data().operations();
		self.operation_indexes
			.iter()
			.filter_map(|&index| operations.get(index))
	}
}

/// The principal of an access-control entry: the party the permissions are
/// granted to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclPrincipal {
	/// A concrete account.
	Account(AccountRef),
	/// Any account presenting a certificate issued by the referenced
	/// certificate.
	Certificate {
		/// Hash of the issuing certificate.
		hash: [u8; 32],
		/// The account the certificate grant is anchored to.
		account: AccountRef,
	},
}

/// An access-control entry granting a principal permissions over a target.
#[derive(Debug, Clone)]
pub struct Acl {
	/// Principal the permissions are granted to.
	pub principal: Option<AclPrincipal>,
	/// Entity the ACL is keyed under.
	pub entity: Option<AccountRef>,
	/// Target the permissions apply to.
	pub target: Option<AccountRef>,
	/// The granted permission set.
	pub permissions: Permissions,
}

/// A certificate and its intermediate chain.
#[derive(Debug, Clone)]
pub struct Certificate {
	/// PEM-encoded certificate.
	pub certificate: String,
	/// PEM-encoded intermediate certificates.
	pub intermediates: Vec<String>,
}

/// Pagination/range bounds for [`KeetaClient::chain_page`](crate::KeetaClient::chain_page).
///
/// `start`/`end` are block-hash cursors; `limit` caps the page size (the node
/// enforces its own maximum).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainQuery {
	/// Start cursor (block hash) to page from.
	pub start: Option<BlockHash>,
	/// End cursor (block hash) to stop at.
	pub end: Option<BlockHash>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// A single page of an account's chain together with the cursor for the next page.
#[derive(Debug, Clone, Default)]
pub struct ChainPage {
	/// The blocks in this page, most recent first.
	pub blocks: Vec<Block>,
	/// Cursor to pass as the next page's [`ChainQuery::start`], or `None` once
	/// the chain is exhausted.
	pub next_key: Option<BlockHash>,
}

/// Pagination/range bounds for
/// [`KeetaClient::history_page`](crate::KeetaClient::history_page) and
/// [`KeetaClient::global_history_page`](crate::KeetaClient::global_history_page).
#[derive(Debug, Clone, Copy, Default)]
pub struct HistoryQuery {
	/// Start cursor (the previous page's last staple id) to page from.
	pub start: Option<VoteBlockHash>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// A single page of history together with the cursor for the next page.
#[derive(Debug, Clone, Default)]
pub struct HistoryPage {
	/// The verified history entries in this page.
	pub entries: Vec<HistoryEntry>,
	/// Cursor to pass as the next page's [`HistoryQuery::start`], or `None`
	/// once the history is exhausted.
	pub next_key: Option<VoteBlockHash>,
}

/// Account metadata as set via [`UserClient::set_info`](crate::UserClient::set_info).
#[derive(Debug, Clone, Default)]
pub struct AccountInfo {
	/// Human-readable name, if set.
	pub name: Option<String>,
	/// Free-form description, if set.
	pub description: Option<String>,
	/// Opaque metadata string, if set.
	pub metadata: Option<String>,
}

/// A snapshot of an account's ledger state.
#[derive(Debug, Clone)]
pub struct AccountState {
	/// Representative account, if one is set.
	pub representative: Option<AccountRef>,
	/// Head block hash, if the account has any blocks.
	pub head: Option<BlockHash>,
	/// Head block height, if known.
	pub height: Option<Amount>,
	/// Account metadata, if the account reports any.
	pub info: Option<AccountInfo>,
	/// Total token supply, present only for token accounts.
	pub supply: Option<Amount>,
	/// Per-token balances held by the account.
	pub balances: Vec<TokenBalance>,
}

/// The future a [`GenerateFeeBlock`] callback returns. The `Send` bound is
/// required on native targets and dropped on wasm, where futures are single-threaded.
#[cfg(not(target_family = "wasm"))]
pub type FeeBlockFuture = Pin<Box<dyn Future<Output = Result<Block, ClientError>> + Send>>;

/// The future a [`GenerateFeeBlock`] callback returns.
#[cfg(target_family = "wasm")]
pub type FeeBlockFuture = Pin<Box<dyn Future<Output = Result<Block, ClientError>>>>;

/// Caller-supplied fee-block factory, invoked mid-transmit with the
/// temporary-round staple and the round's
/// [`fee_token_priority`](TransmitOptions::fee_token_priority) when the
/// representatives' votes require a fee. The returned block joins the
/// permanent round and the published staple.
///
/// Receives a clone of the transmitting client so the callback can chain
/// through [`KeetaClient::build_fee_block`] without capturing one.
#[cfg(not(target_family = "wasm"))]
pub type GenerateFeeBlock = Arc<dyn Fn(KeetaClient, VoteStaple, Vec<AccountRef>) -> FeeBlockFuture + Send + Sync>;

/// Caller-supplied fee-block factory, invoked mid-transmit with the
/// temporary-round staple and the round's
/// [`fee_token_priority`](TransmitOptions::fee_token_priority) when the
/// representatives' votes require a fee.
#[cfg(target_family = "wasm")]
pub type GenerateFeeBlock = Arc<dyn Fn(KeetaClient, VoteStaple, Vec<AccountRef>) -> FeeBlockFuture>;

/// Optional inputs to [`KeetaClient::transmit`](crate::KeetaClient::transmit).
///
/// Constructed with [`Default`] and overridden field-by-field:
///
/// ```
/// use keetanetwork_client::TransmitOptions;
///
/// let options = TransmitOptions::default();
/// assert!(options.generate_fee_block.is_none());
/// assert!(options.quotes.is_empty());
/// ```
#[derive(Clone, Default)]
pub struct TransmitOptions {
	/// Pre-fetched vote quotes to attach to the temporary round. Each quote is
	/// routed to the representative that issued it.
	pub quotes: Vec<VoteQuote>,
	/// Tokens to prefer when a fee entry is payable in several tokens, ranked
	/// highest priority first. An entry with an implicit (`None`) token counts
	/// as the network base token. Empty (the default) prefers the base-token
	/// entry, then the first entry. Handed to
	/// [`generate_fee_block`](Self::generate_fee_block) at invocation, so it
	/// may be set before or after the factory.
	pub fee_token_priority: Vec<AccountRef>,
	/// Fee-block factory invoked when the representatives' votes require a
	/// fee. Absent, a required fee fails with [`ClientError::FeeRequired`].
	/// See [`with_fee_signer`](Self::with_fee_signer) and
	/// [`with_fee_block_from`](Self::with_fee_block_from) for the common
	/// shapes; write the closure by hand only for exotic payment flows.
	pub generate_fee_block: Option<GenerateFeeBlock>,
}

impl TransmitOptions {
	/// Set [`generate_fee_block`](Self::generate_fee_block) to pay any
	/// required fee from `signer`, signing for itself.
	pub fn with_fee_signer(self, signer: &AccountRef) -> Self {
		self.with_fee_block_from(signer, signer)
	}

	/// Set [`generate_fee_block`](Self::generate_fee_block) to pay any
	/// required fee from `account`, signed by `signer` (delegated signing,
	/// e.g. a storage account whose owner signs). For a payer that signs for
	/// itself, prefer [`with_fee_signer`](Self::with_fee_signer).
	pub fn with_fee_block_from(mut self, account: &AccountRef, signer: &AccountRef) -> Self {
		let account = Arc::clone(account);
		let signer = Arc::clone(signer);

		self.generate_fee_block = Some(Arc::new(move |client, staple, priority| {
			let account = Arc::clone(&account);
			let signer = Arc::clone(&signer);

			Box::pin(async move {
				client
					.build_fee_block(&staple, &account, &signer, &priority)
					.await
			})
		}));

		self
	}
}

impl fmt::Debug for TransmitOptions {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("TransmitOptions")
			.field("quotes", &self.quotes)
			.field("fee_token_priority", &self.fee_token_priority)
			.field("generate_fee_block", &self.generate_fee_block.is_some())
			.finish()
	}
}

/// Liveness and statistics for a single representative, as gathered by
/// [`KeetaClient::network_status`](crate::KeetaClient::network_status).
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct RepStatus {
	/// The representative key the status was gathered for.
	pub representative: String,
	/// Whether the representative answered the statistics query.
	pub online: bool,
	/// The representative's statistics, present only when `online`.
	pub stats: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
	use super::*;

	use keetanetwork_block::testing::generate_ed25519_ref;

	#[test]
	fn pending_account_resolves_after_fill() -> Result<(), ClientError> {
		let pending = PendingAccount::default();
		assert!(matches!(pending.get(), Err(ClientError::UnresolvedIdentifier)));

		let account = generate_ed25519_ref(0x01);
		pending.fill(Arc::clone(&account));

		assert_eq!(pending.get()?.to_string(), account.to_string());
		Ok(())
	}

	#[test]
	fn pending_account_fill_is_set_once() {
		let pending = PendingAccount::default();
		let first = generate_ed25519_ref(0x02);
		let second = generate_ed25519_ref(0x03);

		pending.fill(Arc::clone(&first));
		pending.fill(Arc::clone(&second));

		assert!(matches!(pending.get(), Ok(account) if account.to_string() == first.to_string()));
	}

	#[test]
	fn account_or_pending_resolves_both_variants() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x04);
		let resolved: AccountOrPending = (&account).into();
		assert_eq!(resolved.resolve()?.to_string(), account.to_string());

		let pending = PendingAccount::default();
		let operand: AccountOrPending = pending.clone().into();
		assert!(matches!(operand.resolve(), Err(ClientError::UnresolvedIdentifier)));

		pending.fill(Arc::clone(&account));
		assert_eq!(operand.resolve()?.to_string(), account.to_string());
		Ok(())
	}
}
