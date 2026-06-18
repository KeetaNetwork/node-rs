//! Atomic token-swap request construction.
//!
//! A swap is a two-block staple: the maker builds a single block sending one
//! token and receiving another from the counterparty
//! ([`UserClient::create_swap_request`](crate::UserClient::create_swap_request)),
//! then the taker validates that request and appends its matching send
//! ([`UserClient::accept_swap_request`](crate::UserClient::accept_swap_request)).
//! The taker transmits both blocks so neither settles without the other.

use keetanetwork_block::{AccountRef, Amount};

/// The maker's side of a swap: give `send_amount` of `send_token`, expecting
/// `receive_amount` of `receive_token` from `counterparty`.
#[derive(Clone, Debug)]
pub struct CreateSwapRequest {
	/// The account expected to accept and complete the swap.
	pub counterparty: AccountRef,
	/// The token the maker sends.
	pub send_token: AccountRef,
	/// The amount the maker sends.
	pub send_amount: Amount,
	/// The token the maker expects to receive.
	pub receive_token: AccountRef,
	/// The amount the maker expects to receive.
	pub receive_amount: Amount,
	/// Whether the received amount must match exactly.
	pub receive_exact: bool,
}

/// The taker's side of a swap: validate `block` (the maker's request) and,
/// optionally, assert or adjust the amounts via `expected`.
#[derive(Clone, Debug)]
pub struct AcceptSwapRequest {
	/// The maker's swap-request block.
	pub block: keetanetwork_block::Block,
	/// Optional validation/override of the swap's legs.
	pub expected: Option<SwapExpectation>,
}

/// Optional assertions a taker can apply when accepting a swap.
#[derive(Clone, Debug, Default)]
pub struct SwapExpectation {
	/// Validate what the maker is sending (what the taker receives).
	pub receive: Option<SwapTokenAmount>,
	/// Validate, or raise, what the taker sends to the maker.
	pub send: Option<SwapTokenAmount>,
}

/// An optional token and amount used to validate or adjust a swap leg.
#[derive(Clone, Debug, Default)]
pub struct SwapTokenAmount {
	/// The token to assert, if any.
	pub token: Option<AccountRef>,
	/// The amount to assert or set, if any.
	pub amount: Option<Amount>,
}
