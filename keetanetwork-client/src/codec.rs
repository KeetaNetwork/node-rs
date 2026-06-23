//! Transport-agnostic encoding and decoding between the OpenAPI transport types
//! and the domain values.
//!
//! Shared by every [`NodeTransport`](crate::NodeTransport) backend.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keetanetwork_block::{Amount, Block, BlockTime};
use keetanetwork_error::{KeetaNetError, NodeErrorParts, NodeErrorType};
use keetanetwork_vote::{ValidationConfig, Vote, VoteQuote, VoteStaple};
use snafu::ResultExt;

use crate::error::{AmountSnafu, BlockSnafu, ClientError, DecodeSnafu, VoteSnafu};
use crate::generated::types;
use crate::model::{AccountInfo, AccountState, Acl, Certificate, HistoryEntry, Representative, TokenBalance};
use crate::transport::LedgerSide;

impl From<LedgerSide> for types::GetBlockSide {
	fn from(side: LedgerSide) -> Self {
		match side {
			LedgerSide::Main => types::GetBlockSide::Main,
			LedgerSide::Side => types::GetBlockSide::Side,
			LedgerSide::Both => types::GetBlockSide::Both,
		}
	}
}

impl From<LedgerSide> for types::GetBlockVotesSide {
	fn from(side: LedgerSide) -> Self {
		match side {
			LedgerSide::Side => types::GetBlockVotesSide::Side,
			// Vote lookups have no "both"; main is the canonical side.
			LedgerSide::Main | LedgerSide::Both => types::GetBlockVotesSide::Main,
		}
	}
}

/// Decode a node error envelope into the unified [`KeetaNetError`], promoting
/// LEDGER errors to their typed variants and collapsing the rest to a coded
/// carrier.
pub(crate) fn decode_node_error(body: types::Error) -> KeetaNetError {
	let kind = body
		.type_
		.as_deref()
		.map(NodeErrorType::from)
		.unwrap_or_default();
	let idempotent_key = body.idempotent_key.and_then(|key| B64.decode(key).ok());

	NodeErrorParts {
		kind,
		code: body.code.unwrap_or_default(),
		message: body.message,
		should_retry: body.should_retry.unwrap_or(false),
		retry_delay: body.retry_delay.and_then(|delay| u64::try_from(delay).ok()),
		accounts: body.accounts.unwrap_or_default(),
		blockhash: body.blockhash,
		existing_blockhash: body.existing_blockhash,
		account: body.account,
		idempotent_key,
	}
	.into()
}

/// Base64-encode each block's canonical bytes.
pub(crate) fn encode_blocks(blocks: &[Block]) -> Vec<String> {
	blocks
		.iter()
		.map(|block| B64.encode(block.to_bytes()))
		.collect()
}

/// Base64-encode a set of votes for a `createVote` request body.
pub(crate) fn encode_votes(votes: &[Vote]) -> Vec<String> {
	votes
		.iter()
		.map(|vote| B64.encode(vote.as_bytes()))
		.collect()
}

/// Decode and signature-verify a base64 vote from a node response, treating an
/// absent field as [`ClientError::MissingVote`].
pub(crate) fn decode_vote_binary(binary: Option<String>) -> Result<Vote, ClientError> {
	let encoded = binary.ok_or(ClientError::MissingVote)?;
	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	Vote::verify(bytes).context(VoteSnafu)
}

/// Decode and signature-verify a base64 vote quote from a node response,
/// treating an absent field as [`ClientError::MissingQuote`].
pub(crate) fn decode_quote_binary(binary: Option<String>) -> Result<VoteQuote, ClientError> {
	let encoded = binary.ok_or(ClientError::MissingQuote)?;
	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	VoteQuote::verify(bytes).context(VoteSnafu)
}

/// Decode an optional transport block into a domain block.
pub(crate) fn decode_block(block: Option<types::Block>) -> Result<Option<Block>, ClientError> {
	let Some(encoded) = block.and_then(|block| block.binary) else {
		return Ok(None);
	};

	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	let decoded = Block::try_from(bytes.as_slice()).context(BlockSnafu)?;

	Ok(Some(decoded))
}

/// Decode and verify an optional transport vote staple against `moment`.
pub(crate) fn decode_staple(
	staple: Option<types::VoteStaple>,
	moment: BlockTime,
) -> Result<Option<VoteStaple>, ClientError> {
	let Some(encoded) = staple.and_then(|staple| staple.binary) else {
		return Ok(None);
	};

	let bytes = B64.decode(encoded).context(DecodeSnafu)?;
	let staple = VoteStaple::verify(bytes, ValidationConfig::default(), moment).context(VoteSnafu)?;

	Ok(Some(staple))
}

/// Decode and verify a list of transport vote staples against `moment`.
pub(crate) fn decode_staples(
	staples: Vec<types::VoteStaple>,
	moment: BlockTime,
) -> Result<Vec<VoteStaple>, ClientError> {
	staples
		.into_iter()
		.filter_map(|staple| decode_staple(Some(staple), moment).transpose())
		.collect()
}

/// Decode transport history entries into verified domain entries against
/// `moment`.
pub(crate) fn decode_history(
	entries: Vec<types::HistoryEntry>,
	moment: BlockTime,
) -> Result<Vec<HistoryEntry>, ClientError> {
	entries
		.into_iter()
		.filter_map(|entry| match decode_staple(entry.vote_staple, moment) {
			Ok(None) => None,
			Ok(Some(staple)) => Some(Ok(HistoryEntry { staple, id: entry.id, timestamp: entry.timestamp })),
			Err(error) => Some(Err(error)),
		})
		.collect()
}

/// Decode a transport representative entry.
pub(crate) fn decode_representative(rep: types::Representative) -> Result<Representative, ClientError> {
	Ok(Representative {
		account: rep.representative.unwrap_or_default(),
		weight: decode_amount(rep.weight)?,
		api_url: rep.endpoints.and_then(|endpoints| endpoints.api),
	})
}

/// Map a transport ACL row into a domain [`Acl`].
pub(crate) fn decode_acl(row: types::AclRow) -> Acl {
	Acl { principal: row.principal, entity: row.entity, target: row.target, permissions: row.permissions }
}

/// Map a transport certificate into a domain [`Certificate`], dropping entries
/// with no certificate body (the "not found" shape).
pub(crate) fn decode_certificate(cert: types::Certificate) -> Option<Certificate> {
	let certificate = cert.certificate?;
	Some(Certificate { certificate, intermediates: cert.intermediates.unwrap_or_default() })
}

/// Map transport balance entries into domain [`TokenBalance`]s.
pub(crate) fn decode_balances(entries: Vec<types::BalanceEntry>) -> Result<Vec<TokenBalance>, ClientError> {
	entries
		.into_iter()
		.map(|entry| {
			Ok(TokenBalance { token: entry.token.unwrap_or_default(), balance: decode_amount(entry.balance)? })
		})
		.collect()
}

/// Map a transport account-info envelope into the domain [`AccountInfo`].
pub(crate) fn decode_account_info(info: types::AccountInfo) -> AccountInfo {
	AccountInfo { name: info.name, description: info.description, metadata: info.metadata }
}

/// Assemble an [`AccountState`] from the transport fields shared by the single-
/// and batch-account state endpoints.
pub(crate) fn decode_account_state(
	representative: Option<String>,
	head: Option<String>,
	height: Option<String>,
	info: Option<types::AccountInfo>,
	balances: Vec<types::BalanceEntry>,
) -> Result<AccountState, ClientError> {
	let supply = info
		.as_ref()
		.and_then(|info| info.supply.clone())
		.map(|supply| decode_amount(Some(supply)))
		.transpose()?;

	Ok(AccountState {
		representative,
		head,
		height: height
			.map(|height| decode_amount(Some(height)))
			.transpose()?,
		info: info.map(decode_account_info),
		supply,
		balances: decode_balances(balances)?,
	})
}

/// Parse an optional `0x`-hex balance string into an [`Amount`], treating an
/// absent field as zero.
pub(crate) fn decode_amount(balance: Option<String>) -> Result<Amount, ClientError> {
	match balance {
		None => Ok(Amount::default()),
		Some(value) => Amount::from_str(&value).context(AmountSnafu),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decodes_absent_amount_as_zero() {
		assert_eq!(decode_amount(None).unwrap(), Amount::default());
	}

	#[test]
	fn decodes_a_hex_amount() {
		assert_eq!(decode_amount(Some(String::from("0x10"))).unwrap(), Amount::from(16u64));
	}

	#[test]
	fn rejects_a_malformed_amount() {
		assert!(matches!(decode_amount(Some(String::from("nope"))), Err(ClientError::Amount { .. })));
	}

	#[test]
	fn maps_block_side_to_the_wire_variant() {
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Main), types::GetBlockSide::Main));
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Side), types::GetBlockSide::Side));
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Both), types::GetBlockSide::Both));
	}

	#[test]
	fn collapses_vote_side_both_to_main() {
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Side), types::GetBlockVotesSide::Side));
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Main), types::GetBlockVotesSide::Main));
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Both), types::GetBlockVotesSide::Main));
	}
}
