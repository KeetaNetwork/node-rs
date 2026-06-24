//! Error types surfaced by the client.

use alloc::boxed::Box;

use keetanetwork_account::AccountError;
use keetanetwork_block::BlockError;
use keetanetwork_error::KeetaNetError;
use keetanetwork_vote::VoteError;
use num_bigint::ParseBigIntError;
use snafu::Snafu;

/// Failure modes of a client operation.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ClientError {
	/// The request failed at the HTTP/transport layer: connection, timeout,
	/// or response decoding problems. The concrete error is supplied by the
	/// active transport backend, so the orchestrator stays transport-agnostic.
	#[snafu(display("node request failed"))]
	Transport {
		/// Underlying transport error from the backend. `Send + Sync` on native
		/// targets, relaxed on wasm. Browser transport errors are often `!Send`/`!Sync`.
		#[cfg(not(target_family = "wasm"))]
		source: Box<dyn core::error::Error + Send + Sync>,
		/// Underlying transport error from the backend.
		#[cfg(target_family = "wasm")]
		source: Box<dyn core::error::Error>,
	},

	/// The node returned a structured, coded error response.
	#[snafu(display("node returned an error"))]
	Node {
		/// The decoded node error (boxed; the variant is large).
		source: Box<KeetaNetError>,
	},

	/// A base64-encoded field in the response could not be decoded.
	#[snafu(display("malformed base64 in node response"))]
	Decode {
		/// Underlying base64 decoding error.
		source: base64::DecodeError,
	},

	/// A returned vote or staple failed domain decoding or validation.
	#[snafu(display("vote decoding or validation failed"))]
	Vote {
		/// Underlying vote error.
		source: VoteError,
	},

	/// A returned block failed domain decoding.
	#[snafu(display("block decoding failed"))]
	Block {
		/// Underlying block error.
		source: BlockError,
	},

	/// A `$bigint` amount field in the response could not be parsed.
	#[snafu(display("malformed amount in node response"))]
	Amount {
		/// Underlying parse error.
		source: ParseBigIntError,
	},

	/// The `/vote` response omitted the vote field.
	#[snafu(display("node response omitted the vote"))]
	MissingVote,

	/// The `/vote/quote` response omitted the quote field.
	#[snafu(display("node response omitted the vote quote"))]
	MissingQuote,

	/// The `/node/publish` response omitted the publish flag.
	#[snafu(display("node response omitted the publish result"))]
	MissingPublish,

	/// The `/node/version` response omitted the version.
	#[snafu(display("node response omitted the version"))]
	MissingVersion,

	/// The node's votes require a fee block but no signer was supplied to
	/// originate one (use [`send`](crate::KeetaClient::send) or another
	/// signer-bearing path).
	#[snafu(display("node votes require a fee block but no signer was supplied"))]
	FeeRequired,

	/// Deriving the network base token (the implicit fee currency) failed.
	#[snafu(display("network base token derivation failed"))]
	Account {
		/// Underlying account error.
		source: AccountError,
	},

	/// The configured network id is unset or out of range for base-token
	/// derivation.
	#[snafu(display("network id is unset or unsupported for fee token derivation"))]
	UnsupportedNetwork,

	/// The client has no representatives to dispatch to.
	#[snafu(display("no representatives available"))]
	NoRepresentatives,

	/// A request exceeded the configured per-request timeout.
	#[snafu(display("request timed out"))]
	Timeout,

	/// Votes could not reach the configured quorum threshold.
	#[snafu(display("could not reach voting quorum"))]
	QuorumNotReached,

	/// A sync found a missing staple but could not publish it.
	#[snafu(display("sync found a missing staple but could not publish it"))]
	SyncPublishFailed,

	/// Recovery could not assemble or fetch the blocks it needed.
	#[snafu(display("account recovery failed"))]
	RecoverFailed,

	/// A [`PendingAccount`](crate::PendingAccount) was resolved before the
	/// builder that creates the identifier was built.
	#[snafu(display("identifier is unresolved until its builder is built"))]
	UnresolvedIdentifier,

	/// A write operation requires a signer, but the client has none bound.
	#[snafu(display("operation requires a signer but none is bound"))]
	SignerRequired,

	/// A subscription method was called but no WebSocket connector was
	/// configured (see
	/// [`UserClient::with_subscription`](crate::UserClient::with_subscription)).
	#[cfg(feature = "subscribe")]
	#[snafu(display("subscription requires a configured websocket connector"))]
	SubscriptionUnavailable,

	/// A swap-request block did not render to exactly one block.
	#[snafu(display("swap request must render to exactly one block"))]
	SwapMultiBlock,

	/// A swap-request block is missing its SEND operation.
	#[snafu(display("swap request is missing a send operation"))]
	SwapMissingSend,

	/// A swap-request block is missing its RECEIVE operation.
	#[snafu(display("swap request is missing a receive operation"))]
	SwapMissingReceive,

	/// A swap-request block's send/receive accounts do not match the accepting
	/// account.
	#[snafu(display("swap request accounts do not match"))]
	SwapAccountMismatch,

	/// A swap-request leg's token did not match the expected token.
	#[snafu(display("swap request token does not match expected"))]
	SwapTokenMismatch,

	/// A swap-request leg's amount did not match the expected amount.
	#[snafu(display("swap request amount does not match expected"))]
	SwapAmountMismatch,

	/// The taker's send amount is below the maker's requested receive amount.
	#[snafu(display("swap send amount is below the requested receive amount"))]
	SwapAmountTooLow,

	/// The taker's send amount differs from an exact-match receive amount.
	#[snafu(display("swap send amount differs from an exact receive amount"))]
	SwapExactMismatch,
}

impl ClientError {
	/// A stable, machine-readable code for programmatic branching. A
	/// [`Node`](Self::Node) error surfaces the node's own code (e.g.
	/// `LEDGER_*`) when it carries one.
	pub fn code(&self) -> &str {
		match self {
			Self::Transport { .. } => "TRANSPORT",
			Self::Node { source } => source.code().unwrap_or("NODE"),
			Self::Decode { .. } => "DECODE",
			Self::Vote { .. } => "VOTE",
			Self::Block { .. } => "BLOCK",
			Self::Amount { .. } => "AMOUNT",
			Self::MissingVote => "MISSING_VOTE",
			Self::MissingQuote => "MISSING_QUOTE",
			Self::MissingPublish => "MISSING_PUBLISH",
			Self::MissingVersion => "MISSING_VERSION",
			Self::FeeRequired => "FEE_REQUIRED",
			Self::Account { .. } => "ACCOUNT",
			Self::UnsupportedNetwork => "UNSUPPORTED_NETWORK",
			Self::NoRepresentatives => "NO_REPRESENTATIVES",
			Self::Timeout => "TIMEOUT",
			Self::QuorumNotReached => "QUORUM_NOT_REACHED",
			Self::SyncPublishFailed => "SYNC_PUBLISH_FAILED",
			Self::RecoverFailed => "RECOVER_FAILED",
			Self::UnresolvedIdentifier => "UNRESOLVED_IDENTIFIER",
			Self::SignerRequired => "SIGNER_REQUIRED",
			#[cfg(feature = "subscribe")]
			Self::SubscriptionUnavailable => "SUBSCRIPTION_UNAVAILABLE",
			Self::SwapMultiBlock => "SWAP_MULTI_BLOCK",
			Self::SwapMissingSend => "SWAP_MISSING_SEND",
			Self::SwapMissingReceive => "SWAP_MISSING_RECEIVE",
			Self::SwapAccountMismatch => "SWAP_ACCOUNT_MISMATCH",
			Self::SwapTokenMismatch => "SWAP_TOKEN_MISMATCH",
			Self::SwapAmountMismatch => "SWAP_AMOUNT_MISMATCH",
			Self::SwapAmountTooLow => "SWAP_AMOUNT_TOO_LOW",
			Self::SwapExactMismatch => "SWAP_EXACT_MISMATCH",
		}
	}
}
