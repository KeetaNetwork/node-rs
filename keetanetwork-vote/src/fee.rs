//! Fee model and DER codec.
//!
//! A vote may carry an optional fee extension declaring what the issuing
//! representative will charge for the operations covered by the vote. Two
//! on-the-wire shapes are supported:
//!
//! * [`Fees::Single`] - a single fee entry encoded as one DER `SEQUENCE`.
//! * [`Fees::Multiple`] - an alternation of fee entries encoded as
//!   `[0] EXPLICIT { SEQUENCE OF SEQUENCE }`. The payer chooses which of
//!   the listed currencies / pay-to targets to honor.
//!
//! Each [`Fee`] entry carries an [`Amount`], an optional `pay_to`
//! account, and an optional `token` identifier. The `token` field, when
//! set, must be an actual token identifier - non-token accounts are
//! rejected at encode time as [`VoteError::MalformedFeesTokenNotToken`].

use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged};
use keetanetwork_account::KeyPairType;
use keetanetwork_block::{AccountRef, Amount};
use num_bigint::Sign;

use crate::error::VoteError;
use crate::wire::{
	encode_account_octet, encode_amount, encode_bool, parse_account_octet, peek_tag, read_amount, read_bool,
	read_explicit_context, read_implicit_octet_context, read_sequence, unexpected_tag, wrap_explicit_context,
	wrap_implicit_octet_context, wrap_sequence,
};

const FEE_OUTER_TAG: TagNumber = TagNumber::N0;
const FEE_MULTIPLE_TAG: TagNumber = TagNumber::N0;
const FEE_PAY_TO_TAG: TagNumber = TagNumber::N0;
const FEE_TOKEN_TAG: TagNumber = TagNumber::N1;

/// A single fee entry attached to a vote.
#[derive(Debug, Clone)]
pub struct Fee {
	/// Amount the issuer would charge.
	pub amount: Amount,
	/// Account or storage address that should receive the fee.
	pub pay_to: Option<AccountRef>,
	/// Token in which the fee should be paid.
	pub token: Option<AccountRef>,
}

/// Fees attached to a vote, distinguishing the on-the-wire shape used.
#[derive(Debug, Clone)]
pub enum Fees {
	/// Single-entry shape: `[0] EXPLICIT SEQUENCE { ... }`.
	Single {
		/// Whether this fee extension belongs to a [`crate::Vote`] (`false`)
		/// or a quote vote (`true`).
		quote: bool,
		/// The single fee entry.
		fee: Fee,
	},
	/// Multi-entry shape: `[0] EXPLICIT [0] EXPLICIT SEQUENCE OF SEQUENCE`.
	Multiple {
		/// Whether all entries belong to a quote vote.
		quote: bool,
		/// Non-empty list of fee entries; all entries share the same `quote`
		/// flag on the wire.
		fees: Vec<Fee>,
	},
}

impl Fees {
	/// Whether this fees value comes from a quote vote.
	pub fn quote(&self) -> bool {
		match self {
			Fees::Single { quote, .. } | Fees::Multiple { quote, .. } => *quote,
		}
	}

	/// Iterate over every fee entry in declaration order.
	pub fn entries(&self) -> impl Iterator<Item = &Fee> {
		match self {
			Fees::Single { fee, .. } => core::slice::from_ref(fee).iter(),
			Fees::Multiple { fees, .. } => fees.iter(),
		}
	}

	/// Convenience constructor: build the right shape from `entries`. A
	/// single-element input produces a [`Fees::Single`]; multi-element input
	/// produces [`Fees::Multiple`].
	///
	/// Returns [`VoteError::BuilderInvalidFee`] when `entries` is empty.
	pub fn from_entries(quote: bool, entries: Vec<Fee>) -> Result<Self, VoteError> {
		match entries.len() {
			0 => Err(VoteError::BuilderInvalidFee),
			1 => {
				let fee = entries
					.into_iter()
					.next()
					.ok_or(VoteError::BuilderInvalidFee)?;
				Ok(Fees::Single { quote, fee })
			}
			_ => Ok(Fees::Multiple { quote, fees: entries }),
		}
	}

	/// Encode the fees as the DER body of the vote's fees extension
	/// (`extnValue` content, not including the outer OCTET STRING wrapper).
	pub(crate) fn encode_extension_body(&self) -> Result<Vec<u8>, VoteError> {
		let inner = match self {
			Fees::Single { quote, fee } => encode_single_entry(*quote, fee)?,
			Fees::Multiple { quote, fees } => {
				let mut entries = Vec::new();
				for entry in fees {
					entries.extend_from_slice(&encode_single_entry(*quote, entry)?);
				}
				let sequence_of = wrap_sequence(&entries)?;
				wrap_explicit_context(FEE_MULTIPLE_TAG, &sequence_of)?
			}
		};

		wrap_explicit_context(FEE_OUTER_TAG, &inner)
	}

	/// Decode a fees extension body produced by [`Self::encode_extension_body`].
	pub(crate) fn decode_extension_body(bytes: &[u8]) -> Result<Self, VoteError> {
		let mut outer_reader = SliceReader::new(bytes).map_err(|_| VoteError::MalformedFeesFromVoteInvalidInput)?;
		let inner_bytes = read_explicit_context(&mut outer_reader, FEE_OUTER_TAG)
			.map_err(|_| VoteError::MalformedFeesFromVoteInvalidInput)?;

		if !outer_reader.is_finished() {
			return Err(VoteError::MalformedFeesFromVoteInvalidInput);
		}

		let mut inner_reader =
			SliceReader::new(inner_bytes).map_err(|_| VoteError::MalformedFeesFromVoteInvalidInput)?;

		let next = peek_tag(&inner_reader)?;
		match next {
			Tag::Sequence => {
				let entry_bytes = read_sequence(&mut inner_reader)?;
				let (quote, fee) = decode_single_entry(entry_bytes)?;
				if !inner_reader.is_finished() {
					return Err(VoteError::MalformedFeesFromVoteInvalidInput);
				}
				Ok(Fees::Single { quote, fee })
			}
			Tag::ContextSpecific { constructed: true, number } if number == FEE_MULTIPLE_TAG => {
				let multi_bytes = read_explicit_context(&mut inner_reader, FEE_MULTIPLE_TAG)?;
				if !inner_reader.is_finished() {
					return Err(VoteError::MalformedFeesFromVoteInvalidInput);
				}

				let mut sequence_of_reader =
					SliceReader::new(multi_bytes).map_err(|_| VoteError::MalformedFeesFromVoteInvalidInput)?;
				let entries_bytes = read_sequence(&mut sequence_of_reader)?;
				if !sequence_of_reader.is_finished() {
					return Err(VoteError::MalformedFeesFromVoteInvalidInput);
				}

				let mut entries_reader =
					SliceReader::new(entries_bytes).map_err(|_| VoteError::MalformedFeesFromVoteInvalidInput)?;

				let mut entries: Vec<Fee> = Vec::new();
				let mut quote: Option<bool> = None;
				while !entries_reader.is_finished() {
					let entry_bytes = read_sequence(&mut entries_reader)?;
					let (entry_quote, fee) = decode_single_entry(entry_bytes)?;
					match quote {
						None => quote = Some(entry_quote),
						Some(existing) if existing != entry_quote => {
							return Err(VoteError::MalformedFeesQuoteInvalid);
						}
						_ => {}
					}
					entries.push(fee);
				}

				if entries.is_empty() {
					return Err(VoteError::MalformedFeesMultipleFeeEmpty);
				}

				let quote = quote.ok_or(VoteError::MalformedFeesQuoteInvalid)?;
				Ok(Fees::Multiple { quote, fees: entries })
			}
			actual => Err(unexpected_tag(actual)),
		}
	}
}

fn encode_single_entry(quote: bool, fee: &Fee) -> Result<Vec<u8>, VoteError> {
	if fee.amount.as_bigint().sign() == Sign::Minus {
		return Err(VoteError::MalformedFeesAmount);
	}
	if let Some(token) = &fee.token {
		if token.to_keypair_type() != KeyPairType::TOKEN {
			return Err(VoteError::MalformedFeesTokenNotToken);
		}
	}
	if let Some(pay_to) = &fee.pay_to {
		match pay_to.to_keypair_type() {
			KeyPairType::ECDSASECP256K1 | KeyPairType::ECDSASECP256R1 | KeyPairType::ED25519 | KeyPairType::STORAGE => {
			}
			_ => return Err(VoteError::MalformedFeesPayToInvalid),
		}
	}

	let mut content = Vec::new();
	encode_bool(&mut content, quote)?;
	encode_amount(&mut content, &fee.amount)?;
	if let Some(pay_to) = &fee.pay_to {
		let mut buf = Vec::new();
		encode_account_octet(&mut buf, pay_to)?;
		// The schema is `[0] IMPLICIT OCTET STRING`, so the wire form is the
		// raw bytes wrapped in a primitive `[0]` tag (no inner OCTET STRING
		// tag). We strip the OCTET STRING header that `encode_account_octet`
		// just added.
		let stripped = strip_octet_header(&buf)?;
		content.extend_from_slice(&wrap_implicit_octet_context(FEE_PAY_TO_TAG, stripped)?);
	}
	if let Some(token) = &fee.token {
		let mut buf = Vec::new();
		encode_account_octet(&mut buf, token)?;
		let stripped = strip_octet_header(&buf)?;
		content.extend_from_slice(&wrap_implicit_octet_context(FEE_TOKEN_TAG, stripped)?);
	}

	wrap_sequence(&content)
}

fn strip_octet_header(encoded: &[u8]) -> Result<&[u8], VoteError> {
	// `encoded` was produced by `OctetStringRef::encode_to_vec`, which writes
	// `[Tag::OctetString, length, value...]`. Recover `value`.
	let mut reader = SliceReader::new(encoded)?;
	let any = der::asn1::AnyRef::decode(&mut reader)?;
	if any.tag() != Tag::OctetString {
		return Err(unexpected_tag(any.tag()));
	}
	Ok(any.value())
}

fn decode_single_entry(content: &[u8]) -> Result<(bool, Fee), VoteError> {
	let mut reader = SliceReader::new(content)?;
	let quote = read_bool(&mut reader)?;
	let amount = read_amount(&mut reader)?;
	let mut pay_to: Option<AccountRef> = None;
	let mut token: Option<AccountRef> = None;

	while !reader.is_finished() {
		let tag = peek_tag(&reader)?;
		match tag {
			Tag::ContextSpecific { constructed: false, number } if number == FEE_PAY_TO_TAG => {
				let raw = read_implicit_octet_context(&mut reader, FEE_PAY_TO_TAG)?;
				let account = parse_account_octet(raw)?;
				match account.to_keypair_type() {
					KeyPairType::ECDSASECP256K1
					| KeyPairType::ECDSASECP256R1
					| KeyPairType::ED25519
					| KeyPairType::STORAGE => {}
					_ => return Err(VoteError::MalformedFeesPayToInvalid),
				}
				pay_to = Some(account);
			}
			Tag::ContextSpecific { constructed: false, number } if number == FEE_TOKEN_TAG => {
				let raw = read_implicit_octet_context(&mut reader, FEE_TOKEN_TAG)?;
				let account = parse_account_octet(raw)?;
				if account.to_keypair_type() != KeyPairType::TOKEN {
					return Err(VoteError::MalformedFeesTokenNotToken);
				}
				token = Some(account);
			}
			actual => return Err(unexpected_tag(actual)),
		}
	}

	if amount.as_bigint().sign() == Sign::Minus {
		return Err(VoteError::MalformedFeesAmount);
	}

	Ok((quote, Fee { amount, pay_to, token }))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;

	use keetanetwork_account::KeyPairType;
	use keetanetwork_crypto::hash::BlockHash;

	use crate::testing::{ed25519_issuer, secp256k1_issuer};

	fn token_account(seed: &[u8]) -> AccountRef {
		let signer = ed25519_issuer(seed);
		let block_hash = BlockHash::from([7u8; 32]);
		Arc::new(
			signer
				.generate_identifier(KeyPairType::TOKEN, Some(&block_hash), 0)
				.expect("token identifier generation must succeed"),
		)
	}

	fn storage_account(seed: &[u8]) -> AccountRef {
		let signer = ed25519_issuer(seed);
		let block_hash = BlockHash::from([3u8; 32]);
		Arc::new(
			signer
				.generate_identifier(KeyPairType::STORAGE, Some(&block_hash), 0)
				.expect("storage identifier generation must succeed"),
		)
	}

	#[test]
	fn test_single_fee_round_trip_minimal() -> Result<(), VoteError> {
		let fee = Fee { amount: Amount::from(1234u64), pay_to: None, token: None };
		let fees = Fees::Single { quote: false, fee };
		let bytes = fees.encode_extension_body()?;
		let parsed = Fees::decode_extension_body(&bytes)?;
		assert!(matches!(parsed, Fees::Single { quote: false, .. }));
		assert_eq!(parsed.entries().count(), 1);

		let entry = parsed
			.entries()
			.next()
			.expect("single shape must have one entry");
		assert_eq!(entry.amount.as_bigint().to_string(), "1234");
		assert!(entry.pay_to.is_none());
		assert!(entry.token.is_none());
		Ok(())
	}

	#[test]
	fn test_single_fee_round_trip_with_pay_to_and_token() -> Result<(), VoteError> {
		let fee = Fee {
			amount: Amount::from(99u64),
			pay_to: Some(secp256k1_issuer(b"pay-to")),
			token: Some(token_account(b"token-seed")),
		};
		let fees = Fees::Single { quote: true, fee };
		let bytes = fees.encode_extension_body()?;
		let parsed = Fees::decode_extension_body(&bytes)?;
		assert!(matches!(parsed, Fees::Single { quote: true, .. }));

		let entry = parsed
			.entries()
			.next()
			.expect("single shape must have one entry");
		assert_eq!(entry.amount.as_bigint().to_string(), "99");
		assert!(entry.pay_to.is_some());
		assert!(entry.token.is_some());
		Ok(())
	}

	#[test]
	fn test_multi_fee_round_trip() -> Result<(), VoteError> {
		let fees = Fees::Multiple {
			quote: false,
			fees: vec![
				Fee { amount: Amount::from(1u64), pay_to: None, token: None },
				Fee { amount: Amount::from(2u64), pay_to: None, token: None },
				Fee { amount: Amount::from(3u64), pay_to: None, token: None },
			],
		};
		let bytes = fees.encode_extension_body()?;
		let parsed = Fees::decode_extension_body(&bytes)?;
		assert!(matches!(parsed, Fees::Multiple { quote: false, .. }));

		let amounts: Vec<String> = parsed
			.entries()
			.map(|fee| fee.amount.as_bigint().to_string())
			.collect();
		assert_eq!(amounts, vec!["1", "2", "3"]);
		Ok(())
	}

	#[test]
	fn test_storage_pay_to_allowed() -> Result<(), VoteError> {
		let fee = Fee { amount: Amount::from(7u64), pay_to: Some(storage_account(b"st")), token: None };
		let fees = Fees::Single { quote: false, fee };
		let bytes = fees.encode_extension_body()?;
		assert!(Fees::decode_extension_body(&bytes).is_ok());
		Ok(())
	}

	#[test]
	fn test_negative_amount_rejected() {
		let fee = Fee { amount: Amount::from(-1i64), pay_to: None, token: None };
		let fees = Fees::Single { quote: false, fee };
		assert!(matches!(fees.encode_extension_body(), Err(VoteError::MalformedFeesAmount)));
	}

	#[test]
	fn test_non_token_token_rejected() {
		let fake_token = secp256k1_issuer(b"fake-token");
		let fee = Fee { amount: Amount::from(1u64), pay_to: None, token: Some(fake_token) };
		let fees = Fees::Single { quote: false, fee };
		assert!(matches!(fees.encode_extension_body(), Err(VoteError::MalformedFeesTokenNotToken)));
	}

	#[test]
	fn test_from_entries_arity_dispatch() -> Result<(), VoteError> {
		let one = vec![Fee { amount: Amount::from(1u64), pay_to: None, token: None }];
		assert!(matches!(Fees::from_entries(false, one)?, Fees::Single { .. }));

		let many = vec![
			Fee { amount: Amount::from(1u64), pay_to: None, token: None },
			Fee { amount: Amount::from(2u64), pay_to: None, token: None },
		];
		assert!(matches!(Fees::from_entries(false, many)?, Fees::Multiple { .. }));
		assert!(matches!(Fees::from_entries(false, Vec::new()), Err(VoteError::BuilderInvalidFee)));
		Ok(())
	}

	#[test]
	fn test_quote_bit_propagates_per_entry() -> Result<(), VoteError> {
		let fees = Fees::Multiple {
			quote: true,
			fees: vec![
				Fee { amount: Amount::from(1u64), pay_to: None, token: None },
				Fee { amount: Amount::from(2u64), pay_to: None, token: None },
			],
		};
		let bytes = fees.encode_extension_body()?;
		let parsed = Fees::decode_extension_body(&bytes)?;
		assert!(parsed.quote());
		Ok(())
	}

	#[test]
	fn test_extra_data_after_outer_rejected() -> Result<(), VoteError> {
		let fees = Fees::Single { quote: false, fee: Fee { amount: Amount::from(1u64), pay_to: None, token: None } };
		let mut bytes = fees.encode_extension_body()?;
		bytes.push(0xFF);
		assert!(matches!(Fees::decode_extension_body(&bytes), Err(VoteError::MalformedFeesFromVoteInvalidInput)));
		Ok(())
	}

	#[test]
	fn test_entries_iterator_lengths() {
		let single = Fees::Single { quote: false, fee: Fee { amount: Amount::from(1u64), pay_to: None, token: None } };
		assert_eq!(single.entries().count(), 1);

		let multi = Fees::Multiple {
			quote: false,
			fees: vec![Fee { amount: Amount::from(1u64), pay_to: None, token: None }; 4],
		};
		assert_eq!(multi.entries().count(), 4);
	}
}
