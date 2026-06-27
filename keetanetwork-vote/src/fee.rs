//! Fee model for the optional `fees` extension carried by a vote.
//!
//! A vote may carry a fee schedule declaring what the issuing
//! representative will charge for the operations the vote covers. Two
//! transport shapes are supported:
//!
//! * [`Fees::Single`] - one fee entry.
//! * [`Fees::Multiple`] - a list of alternative fee entries; the payer
//!   chooses which currency / pay-to target to honour.
//!
//! Each [`Fee`] entry carries an [`Amount`], an optional `pay_to`
//! account, and an optional `token` identifier. The `token` field, when
//! set, must be an actual token identifier - non-token accounts are
//! rejected at encode time as [`VoteError::MalformedFeesTokenNotToken`].

use alloc::sync::Arc;
use alloc::vec::Vec;

use hex::FromHex;
use keetanetwork_account::{GenericAccount, KeyPairType};
use keetanetwork_asn1::vote as transport;
use keetanetwork_block::{AccountRef, Amount};
use num_bigint::Sign;

use crate::error::VoteError;

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

impl<'a> IntoIterator for &'a Fees {
	type Item = &'a Fee;
	type IntoIter = core::slice::Iter<'a, Fee>;

	fn into_iter(self) -> Self::IntoIter {
		match self {
			Fees::Single { fee, .. } => core::slice::from_ref(fee).iter(),
			Fees::Multiple { fees, .. } => fees.iter(),
		}
	}
}

/// Fees attached to a vote, distinguishing the single-entry and
/// multi-entry shapes.
#[derive(Debug, Clone)]
pub enum Fees {
	/// Single-entry shape.
	Single {
		/// Whether this fee extension belongs to a [`crate::Vote`] (`false`)
		/// or a quote vote (`true`).
		quote: bool,
		/// The single fee entry.
		fee: Fee,
	},
	/// Multi-entry shape.
	Multiple {
		/// Whether all entries belong to a quote vote.
		quote: bool,
		/// Non-empty list of fee entries; all entries share the same
		/// `quote` flag in the transport.
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
	///
	/// Equivalent to `(&fees).into_iter()` and offered as an inherent
	/// method for legibility at call sites that want to chain combinators
	/// without an explicit borrow.
	pub fn entries(&self) -> core::slice::Iter<'_, Fee> {
		self.into_iter()
	}

	/// Convenience constructor: build the right shape from `entries`. A
	/// single-element input produces a [`Fees::Single`]; multi-element
	/// input produces [`Fees::Multiple`].
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

	/// Project this domain value to the codec-neutral transport form.
	pub(crate) fn to_transport(&self) -> Result<transport::Fees, VoteError> {
		match self {
			Fees::Single { quote, fee } => Ok(transport::Fees::Single(fee_to_entry(*quote, fee)?)),
			Fees::Multiple { quote, fees } => {
				let mut entries = Vec::with_capacity(fees.len());
				for fee in fees {
					entries.push(fee_to_entry(*quote, fee)?);
				}

				Ok(transport::Fees::Multiple(entries))
			}
		}
	}

	/// Lift a transport-decoded value into a domain [`Fees`], enforcing
	/// per-entry invariants (positive amount, valid `pay_to`, token-only
	/// `token`).
	pub(crate) fn from_transport(value: transport::Fees) -> Result<Self, VoteError> {
		match value {
			transport::Fees::Single(entry) => {
				let (quote, fee) = entry_to_fee(entry)?;
				Ok(Fees::Single { quote, fee })
			}
			transport::Fees::Multiple(entries) => {
				if entries.is_empty() {
					return Err(VoteError::MalformedFeesMultipleFeeEmpty);
				}

				let mut quote: Option<bool> = None;
				let mut fees: Vec<Fee> = Vec::with_capacity(entries.len());
				for entry in entries {
					let (entry_quote, fee) = entry_to_fee(entry)?;
					match quote {
						None => quote = Some(entry_quote),
						Some(existing) if existing != entry_quote => {
							return Err(VoteError::MalformedFeesInvalidQuoteValue);
						}
						_ => {}
					}

					fees.push(fee);
				}

				let quote = quote.ok_or(VoteError::MalformedFeesInvalidQuoteValue)?;
				Ok(Fees::Multiple { quote, fees })
			}
		}
	}
}

fn fee_to_entry(quote: bool, fee: &Fee) -> Result<transport::FeeEntry, VoteError> {
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

	Ok(transport::FeeEntry {
		quote,
		amount: fee.amount.as_bigint().clone(),
		pay_to: fee
			.pay_to
			.as_ref()
			.map(|account| account.to_public_key_with_type()),
		token: fee
			.token
			.as_ref()
			.map(|account| account.to_public_key_with_type()),
	})
}

fn entry_to_fee(entry: transport::FeeEntry) -> Result<(bool, Fee), VoteError> {
	if entry.amount.sign() == Sign::Minus {
		return Err(VoteError::MalformedFeesAmount);
	}

	let pay_to = entry
		.pay_to
		.map(|bytes| account_from_octet(&bytes, AccountKind::PayTo))
		.transpose()?;
	let token = entry
		.token
		.map(|bytes| account_from_octet(&bytes, AccountKind::Token))
		.transpose()?;

	Ok((entry.quote, Fee { amount: Amount::from(entry.amount), pay_to, token }))
}

#[derive(Clone, Copy)]
enum AccountKind {
	PayTo,
	Token,
}

fn account_from_octet(bytes: &[u8], kind: AccountKind) -> Result<AccountRef, VoteError> {
	let account = GenericAccount::from_hex(hex::encode(bytes)).map_err(|_| match kind {
		AccountKind::PayTo => VoteError::MalformedFeesPayToInvalid,
		AccountKind::Token => VoteError::MalformedFeesTokenNotToken,
	})?;
	match kind {
		AccountKind::PayTo => match account.to_keypair_type() {
			KeyPairType::ECDSASECP256K1 | KeyPairType::ECDSASECP256R1 | KeyPairType::ED25519 | KeyPairType::STORAGE => {
			}
			_ => return Err(VoteError::MalformedFeesPayToInvalid),
		},
		AccountKind::Token => {
			if account.to_keypair_type() != KeyPairType::TOKEN {
				return Err(VoteError::MalformedFeesTokenNotToken);
			}
		}
	}

	Ok(Arc::new(account))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::{multi_fees, secp256k1_issuer, simple_fee, single_fees, storage_account, token_account};

	fn round_trip(fees: &Fees) -> Result<Fees, VoteError> {
		Fees::from_transport(fees.to_transport()?)
	}

	#[test]
	fn test_single_fee_round_trip_minimal() -> Result<(), VoteError> {
		let fees = single_fees(1234);
		let parsed = round_trip(&fees)?;
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
		let parsed = round_trip(&fees)?;
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
		let fees = multi_fees(false, [1, 2, 3]);
		let parsed = round_trip(&fees)?;
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
		round_trip(&fees)?;
		Ok(())
	}

	#[test]
	fn test_negative_amount_rejected() {
		let fee = Fee { amount: Amount::from(-1i64), pay_to: None, token: None };
		let fees = Fees::Single { quote: false, fee };
		assert!(matches!(fees.to_transport(), Err(VoteError::MalformedFeesAmount)));
	}

	#[test]
	fn test_non_token_token_rejected() {
		let fake_token = secp256k1_issuer(b"fake-token");
		let fee = Fee { amount: Amount::from(1u64), pay_to: None, token: Some(fake_token) };
		let fees = Fees::Single { quote: false, fee };
		assert!(matches!(fees.to_transport(), Err(VoteError::MalformedFeesTokenNotToken)));
	}

	#[test]
	fn test_from_entries_arity_dispatch() -> Result<(), VoteError> {
		assert!(matches!(Fees::from_entries(false, vec![simple_fee(1)])?, Fees::Single { .. }));
		assert!(matches!(Fees::from_entries(false, vec![simple_fee(1), simple_fee(2)])?, Fees::Multiple { .. }));
		assert!(matches!(Fees::from_entries(false, Vec::new()), Err(VoteError::BuilderInvalidFee)));
		Ok(())
	}

	#[test]
	fn test_quote_bit_propagates_per_entry() -> Result<(), VoteError> {
		let parsed = round_trip(&multi_fees(true, [1, 2]))?;
		assert!(parsed.quote());
		Ok(())
	}

	#[test]
	fn test_entries_iterator_lengths() {
		assert_eq!(single_fees(1).entries().count(), 1);
		assert_eq!(multi_fees(false, [1, 1, 1, 1]).entries().count(), 4);
	}

	#[test]
	fn test_into_iterator_matches_entries() {
		let fees = multi_fees(false, [1, 2, 3]);
		let via_into: Vec<&Fee> = (&fees).into_iter().collect();
		let via_entries: Vec<&Fee> = fees.entries().collect();
		assert_eq!(via_into.len(), via_entries.len());
		assert!(via_into
			.iter()
			.zip(via_entries.iter())
			.all(|(a, b)| core::ptr::eq(*a, *b)));
	}

	#[test]
	fn test_for_loop_over_fees() {
		let fees = multi_fees(false, [10, 20]);
		let amounts: Vec<String> = (&fees)
			.into_iter()
			.map(|fee| fee.amount.as_bigint().to_string())
			.collect();
		assert_eq!(amounts, vec!["10", "20"]);
	}
}
