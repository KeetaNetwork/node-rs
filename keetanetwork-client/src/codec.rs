//! Transport-agnostic encoding and decoding between the OpenAPI transport types
//! and the domain values.
//!
//! Shared by every [`NodeTransport`](crate::NodeTransport) backend.

use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use alloc::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use keetanetwork_account::GenericAccount;
use keetanetwork_block::{AccountRef, Amount, Block, BlockTime, Permissions};
use keetanetwork_crypto::error::CryptoError;
use keetanetwork_error::{KeetaNetError, NodeErrorParts, NodeErrorType};
use keetanetwork_vote::{ValidationConfig, Vote, VoteQuote, VoteStaple};
use snafu::ResultExt;

use crate::error::{
	AccountSnafu, AmountSnafu, BlockSnafu, ClientError, DecodeSnafu, HashSnafu, MomentSnafu, PermissionSnafu, VoteSnafu,
};
use crate::generated::types;
use crate::model::{
	AccountInfo, AccountState, Acl, AclPrincipal, Certificate, HistoryEntry, LedgerChecksum, Representative,
	TokenBalance,
};
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

impl From<LedgerSide> for types::GetBlockFromIdempotentSide {
	fn from(side: LedgerSide) -> Self {
		match side {
			LedgerSide::Main => types::GetBlockFromIdempotentSide::Main,
			LedgerSide::Side => types::GetBlockFromIdempotentSide::Side,
			LedgerSide::Both => types::GetBlockFromIdempotentSide::Both,
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
			Ok(Some(staple)) => Some(decode_history_entry(staple, entry.id, entry.timestamp)),
			Err(error) => Some(Err(error)),
		})
		.collect()
}

/// Assemble a verified [`HistoryEntry`] from its decoded staple and the
/// transport id/timestamp fields.
fn decode_history_entry(
	staple: VoteStaple,
	id: Option<String>,
	timestamp: Option<String>,
) -> Result<HistoryEntry, ClientError> {
	Ok(HistoryEntry { staple, id: decode_hash(id)?, timestamp: decode_moment(timestamp)? })
}

/// Parse an optional ISO 8601 timestamp field into a [`BlockTime`], treating
/// an absent field as `None`.
pub(crate) fn decode_moment(timestamp: Option<String>) -> Result<Option<BlockTime>, ClientError> {
	timestamp
		.map(|value| BlockTime::from_str(&value).context(MomentSnafu))
		.transpose()
}

/// Parse a required account address field into an [`AccountRef`], treating an
/// absent field as malformed.
pub(crate) fn decode_account(address: Option<String>) -> Result<AccountRef, ClientError> {
	let value = address.unwrap_or_default();
	let account = GenericAccount::from_str(&value).context(AccountSnafu)?;
	Ok(Arc::new(account))
}

/// Parse an optional account address field into an [`AccountRef`], treating an
/// absent field as `None`.
pub(crate) fn decode_account_opt(address: Option<String>) -> Result<Option<AccountRef>, ClientError> {
	address.map(|value| decode_account(Some(value))).transpose()
}

/// Decode a transport representative entry.
pub(crate) fn decode_representative(rep: types::Representative) -> Result<Representative, ClientError> {
	Ok(Representative {
		account: decode_account(rep.representative)?,
		weight: decode_amount(rep.weight)?,
		api_url: rep.endpoints.and_then(|endpoints| endpoints.api),
	})
}

/// Decode the ledger checksum response into a domain [`LedgerChecksum`].
pub(crate) fn decode_checksum(checksum: types::GetLedgerChecksumResponse) -> Result<LedgerChecksum, ClientError> {
	Ok(LedgerChecksum {
		checksum: decode_amount(checksum.checksum)?,
		moment: decode_moment(checksum.moment)?,
		moment_range: checksum.moment_range,
	})
}

/// Map a transport ACL row into a domain [`Acl`].
pub(crate) fn decode_acl(row: types::AclRow) -> Result<Acl, ClientError> {
	Ok(Acl {
		principal: decode_acl_principal(row.principal_type, row.principal)?,
		entity: decode_account_opt(row.entity)?,
		target: decode_account_opt(row.target)?,
		permissions: decode_permissions(row.permissions)?,
	})
}

/// Decode the `[base, external]` permission bitmaps into a [`Permissions`]
/// set, treating absent entries as empty bitmaps.
pub(crate) fn decode_permissions(bitmaps: Vec<String>) -> Result<Permissions, ClientError> {
	let mut parts = bitmaps.into_iter();
	let base = decode_amount(parts.next())?;
	let external = decode_amount(parts.next())?;

	Permissions::from_bigints(base.as_bigint().clone(), external.as_bigint().clone()).context(PermissionSnafu)
}

/// Decode an ACL principal from its wire shape: an account address string
/// when `kind` is `ACCOUNT` (or absent), or a certificate object when
/// `CERTIFICATE`.
fn decode_acl_principal(
	kind: Option<types::AclRowPrincipalType>,
	principal: Option<serde_json::Value>,
) -> Result<Option<AclPrincipal>, ClientError> {
	let Some(value) = principal else {
		return Ok(None);
	};

	match kind {
		Some(types::AclRowPrincipalType::Certificate) => Ok(Some(decode_certificate_principal(&value)?)),
		Some(types::AclRowPrincipalType::Account) | None => {
			let address = value.as_str().ok_or(ClientError::AclPrincipal)?;
			let decoded = decode_account(Some(address.into()))?;

			Ok(Some(AclPrincipal::Account(decoded)))
		}
	}
}

/// Decode a certificate principal object carrying the issuing certificate
/// hash and its anchor account.
fn decode_certificate_principal(value: &serde_json::Value) -> Result<AclPrincipal, ClientError> {
	let hash_hex = value
		.get("certificate")
		.and_then(serde_json::Value::as_str)
		.ok_or(ClientError::AclPrincipal)?;
	let account = value
		.get("certificateAccount")
		.and_then(serde_json::Value::as_str)
		.ok_or(ClientError::AclPrincipal)?;

	let bytes = hex::decode(hash_hex).map_err(|_| ClientError::AclPrincipal)?;
	let hash: [u8; 32] = bytes.try_into().map_err(|_| ClientError::AclPrincipal)?;
	let account = decode_account(Some(account.into()))?;

	Ok(AclPrincipal::Certificate { hash, account })
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
		.map(|entry| Ok(TokenBalance { token: decode_account(entry.token)?, balance: decode_amount(entry.balance)? }))
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
		representative: decode_account_opt(representative)?,
		head: decode_hash(head)?,
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

/// Parse an optional hex hash field into its domain digest type, treating an
/// absent field as `None`.
pub(crate) fn decode_hash<T>(hash: Option<String>) -> Result<Option<T>, ClientError>
where
	T: FromStr<Err = CryptoError>,
{
	hash.map(|value| T::from_str(&value).context(HashSnafu))
		.transpose()
}

#[cfg(test)]
mod tests {
	use super::*;

	use alloc::vec;

	use keetanetwork_block::testing::generate_ed25519_ref;
	use keetanetwork_block::BaseFlag;

	#[test]
	fn decodes_absent_amount_as_zero() {
		assert_eq!(decode_amount(None).unwrap(), Amount::default());
	}

	#[test]
	fn decodes_a_required_account() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x05);
		let decoded = decode_account(Some(account.to_string()))?;
		assert_eq!(decoded, account);
		Ok(())
	}

	#[test]
	fn rejects_an_absent_required_account() {
		assert!(matches!(decode_account(None), Err(ClientError::Account { .. })));
	}

	#[test]
	fn decodes_an_absent_optional_account_as_none() -> Result<(), ClientError> {
		assert_eq!(decode_account_opt(None)?, None);
		Ok(())
	}

	#[test]
	fn decodes_permission_bitmaps() -> Result<(), ClientError> {
		let permissions = decode_permissions(vec![String::from("0x1"), String::from("0x0")])?;
		assert!(permissions.has(&[BaseFlag::Access], &[]));
		Ok(())
	}

	#[test]
	fn decodes_absent_bitmaps_as_an_empty_set() -> Result<(), ClientError> {
		let permissions = decode_permissions(vec![])?;
		assert!(permissions.base().flags().is_empty());
		Ok(())
	}

	#[test]
	fn rejects_a_malformed_bitmap() {
		let decoded = decode_permissions(vec![String::from("nope")]);
		assert!(matches!(decoded, Err(ClientError::Amount { .. })));
	}

	#[test]
	fn decodes_an_account_principal() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x06);
		let decoded = decode_acl_principal(
			Some(types::AclRowPrincipalType::Account),
			Some(serde_json::Value::String(account.to_string())),
		)?;
		assert!(matches!(decoded, Some(AclPrincipal::Account(principal)) if principal == account));
		Ok(())
	}

	#[test]
	fn decodes_a_certificate_principal() -> Result<(), ClientError> {
		let account = generate_ed25519_ref(0x07);
		let value = serde_json::json!({
			"certificate": "ab".repeat(32),
			"certificateAccount": account.to_string(),
		});

		let decoded = decode_acl_principal(Some(types::AclRowPrincipalType::Certificate), Some(value))?;
		assert!(matches!(
			decoded,
			Some(AclPrincipal::Certificate { hash, account: anchor }) if hash == [0xABu8; 32] && anchor == account
		));
		Ok(())
	}

	#[test]
	fn decodes_an_absent_principal_as_none() -> Result<(), ClientError> {
		assert_eq!(decode_acl_principal(None, None)?, None);
		Ok(())
	}

	#[test]
	fn rejects_a_malformed_principal_shape() {
		let decoded = decode_acl_principal(None, Some(serde_json::Value::from(7)));
		assert!(matches!(decoded, Err(ClientError::AclPrincipal)));
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
	fn decodes_absent_hash_as_none() -> Result<(), ClientError> {
		let decoded: Option<keetanetwork_block::BlockHash> = decode_hash(None)?;
		assert_eq!(decoded, None);
		Ok(())
	}

	#[test]
	fn decodes_a_hex_hash() -> Result<(), ClientError> {
		let hash = keetanetwork_block::BlockHash::from([0xABu8; 32]);
		let decoded: Option<keetanetwork_block::BlockHash> = decode_hash(Some(hash.to_string()))?;
		assert_eq!(decoded, Some(hash));
		Ok(())
	}

	#[test]
	fn rejects_a_malformed_hash() {
		let decoded: Result<Option<keetanetwork_block::BlockHash>, ClientError> =
			decode_hash(Some(String::from("nope")));
		assert!(matches!(decoded, Err(ClientError::Hash { .. })));
	}

	#[test]
	fn decodes_absent_moment_as_none() -> Result<(), ClientError> {
		assert_eq!(decode_moment(None)?, None);
		Ok(())
	}

	#[test]
	fn decodes_an_iso_moment() -> Result<(), ClientError> {
		let decoded = decode_moment(Some(String::from("2025-01-02T03:04:05.123Z")))?;
		assert_eq!(decoded.map(|moment| moment.to_string()).as_deref(), Some("2025-01-02T03:04:05.123Z"));
		Ok(())
	}

	#[test]
	fn rejects_a_malformed_moment() {
		assert!(matches!(decode_moment(Some(String::from("nope"))), Err(ClientError::Moment { .. })));
	}

	#[test]
	fn maps_block_side_to_the_wire_variant() {
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Main), types::GetBlockSide::Main));
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Side), types::GetBlockSide::Side));
		assert!(matches!(types::GetBlockSide::from(LedgerSide::Both), types::GetBlockSide::Both));
	}

	#[test]
	fn maps_idempotent_side_to_the_wire_variant() {
		assert!(matches!(
			types::GetBlockFromIdempotentSide::from(LedgerSide::Main),
			types::GetBlockFromIdempotentSide::Main
		));
		assert!(matches!(
			types::GetBlockFromIdempotentSide::from(LedgerSide::Side),
			types::GetBlockFromIdempotentSide::Side
		));
		assert!(matches!(
			types::GetBlockFromIdempotentSide::from(LedgerSide::Both),
			types::GetBlockFromIdempotentSide::Both
		));
	}

	#[test]
	fn collapses_vote_side_both_to_main() {
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Side), types::GetBlockVotesSide::Side));
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Main), types::GetBlockVotesSide::Main));
		assert!(matches!(types::GetBlockVotesSide::from(LedgerSide::Both), types::GetBlockVotesSide::Main));
	}
}
