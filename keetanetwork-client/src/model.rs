//! Domain-typed request/response models exposed by
//! [`KeetaClient`](crate::KeetaClient).

use alloc::string::String;
use alloc::vec::Vec;

use keetanetwork_block::{AccountRef, Amount};
use keetanetwork_vote::{VoteQuote, VoteStaple};

/// A token balance entry for an account.
#[derive(Debug, Clone)]
pub struct TokenBalance {
	/// Token account address.
	pub token: String,
	/// Settled balance.
	pub balance: Amount,
	/// Pending (unreceived) balance.
	pub pending: Amount,
}

/// A representative and its voting weight.
#[derive(Debug, Clone)]
pub struct Representative {
	/// Representative account address.
	pub account: String,
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
	/// Approximate moment the checksum was taken (ISO 8601).
	pub moment: Option<String>,
	/// Half the measurement window, in milliseconds.
	pub moment_range: Option<f64>,
}

/// A history entry: a verified vote staple with its id and timestamp.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
	/// The verified vote staple.
	pub staple: VoteStaple,
	/// Hexadecimal vote staple id.
	pub id: Option<String>,
	/// ISO 8601 timestamp.
	pub timestamp: Option<String>,
}

/// An access-control entry granting a principal permissions over a target.
#[derive(Debug, Clone)]
pub struct Acl {
	/// Principal the permissions are granted to.
	pub principal: Option<String>,
	/// Entity the ACL is keyed under.
	pub entity: Option<String>,
	/// Target the permissions apply to.
	pub target: Option<String>,
	/// Permission bitmaps as `0x`-prefixed hexadecimal values.
	pub permissions: Vec<String>,
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
#[derive(Debug, Clone, Default)]
pub struct ChainQuery {
	/// Start cursor (block hash) to page from.
	pub start: Option<String>,
	/// End cursor (block hash) to stop at.
	pub end: Option<String>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// Pagination/range bounds for
/// [`KeetaClient::history_page`](crate::KeetaClient::history_page) and
/// [`KeetaClient::global_history_page`](crate::KeetaClient::global_history_page).
#[derive(Debug, Clone, Default)]
pub struct HistoryQuery {
	/// Start cursor (block hash) to page from.
	pub start: Option<String>,
	/// Maximum entries to return in the page.
	pub limit: Option<i64>,
}

/// A snapshot of an account's ledger state.
#[derive(Debug, Clone)]
pub struct AccountState {
	/// Representative account address, if one is set.
	pub representative: Option<String>,
	/// Head block hash (hex), if the account has any blocks.
	pub head: Option<String>,
	/// Head block height, if known.
	pub height: Option<Amount>,
	/// Total token supply, present only for token accounts.
	pub supply: Option<Amount>,
	/// Per-token balances held by the account.
	pub balances: Vec<TokenBalance>,
}

/// Optional inputs to [`KeetaClient::transmit`](crate::KeetaClient::transmit).
///
/// Constructed with [`Default`] and overridden field-by-field:
///
/// ```
/// use keetanetwork_client::TransmitOptions;
///
/// let options = TransmitOptions::default();
/// assert!(options.fee_signer.is_none());
/// assert!(options.quotes.is_empty());
/// ```
#[derive(Clone, Debug, Default)]
pub struct TransmitOptions {
	/// Account that originates and signs a
	/// [`BlockPurpose::Fee`](keetanetwork_block::BlockPurpose::Fee) block when
	/// the representatives' votes require a fee. Absent, a required fee fails
	/// with [`ClientError::FeeRequired`](crate::ClientError::FeeRequired).
	pub fee_signer: Option<AccountRef>,
	/// Pre-fetched vote quotes to attach to the temporary round. Each quote is
	/// routed to the representative that issued it.
	pub quotes: Vec<VoteQuote>,
	/// Tokens to prefer when a fee entry is payable in several tokens, ranked
	/// highest priority first. An entry with an implicit (`None`) token counts
	/// as the network base token. Empty (the default) prefers the base-token
	/// entry, then the first entry.
	pub fee_token_priority: Vec<AccountRef>,
}
