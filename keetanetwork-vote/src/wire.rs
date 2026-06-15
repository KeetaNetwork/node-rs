//! Shared DER encoding/decoding helpers for the vote crate.

use std::sync::Arc;

use der::asn1::{AnyRef, BitStringRef, OctetStringRef, Utf8StringRef};
use der::{Decode, Encode, ErrorKind, Length, SliceReader, Tag, TagNumber, Tagged};
use hex::FromHex;
use keetanetwork_account::{AccountError, GenericAccount};
use keetanetwork_block::{AccountRef, Amount};
use num_bigint::BigInt;

use crate::error::VoteError;

pub(crate) fn unexpected_tag(actual: Tag) -> VoteError {
	der::Error::new(ErrorKind::TagUnexpected { expected: None, actual }, Length::ZERO).into()
}

// --- Encoding -------------------------------------------------------------

pub(crate) fn encode_octet(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), VoteError> {
	OctetStringRef::new(bytes)?.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_bool(out: &mut Vec<u8>, value: bool) -> Result<(), VoteError> {
	value.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_amount(out: &mut Vec<u8>, value: &Amount) -> Result<(), VoteError> {
	value.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_account_octet(out: &mut Vec<u8>, account: &AccountRef) -> Result<(), VoteError> {
	encode_octet(out, &account.to_public_key_with_type())
}

pub(crate) fn wrap_sequence(content: &[u8]) -> Result<Vec<u8>, VoteError> {
	Ok(AnyRef::new(Tag::Sequence, content)?.to_der()?)
}

pub(crate) fn wrap_explicit_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, VoteError> {
	let tag = Tag::ContextSpecific { constructed: true, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

/// Wrap content bytes in an `[N] IMPLICIT` primitive context tag.
///
/// Used for OCTET STRING fields that carry a context-specific tag instead of
/// the universal OCTET STRING tag.
pub(crate) fn wrap_implicit_octet_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, VoteError> {
	let tag = Tag::ContextSpecific { constructed: false, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

// --- Decoding -------------------------------------------------------------

pub(crate) fn read_sequence<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], VoteError> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Sequence {
		return Err(unexpected_tag(any.tag()));
	}
	Ok(any.value())
}

pub(crate) fn read_octet<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], VoteError> {
	Ok(OctetStringRef::decode(reader)?.as_bytes())
}

pub(crate) fn read_bool(reader: &mut SliceReader<'_>) -> Result<bool, VoteError> {
	Ok(bool::decode(reader)?)
}

pub(crate) fn read_amount(reader: &mut SliceReader<'_>) -> Result<Amount, VoteError> {
	Ok(Amount::decode(reader)?)
}

pub(crate) fn read_bigint(reader: &mut SliceReader<'_>) -> Result<BigInt, VoteError> {
	Ok(read_amount(reader)?.into())
}

pub(crate) fn read_utf8(reader: &mut SliceReader<'_>) -> Result<String, VoteError> {
	Ok(Utf8StringRef::decode(reader)?.as_str().to_string())
}

pub(crate) fn read_bit_string<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], VoteError> {
	let value = BitStringRef::decode(reader)?;
	value
		.as_bytes()
		.ok_or(VoteError::MalformedVoteSignatureValue)
}

/// Read an `[N] EXPLICIT` context-specific tag and return its contents.
pub(crate) fn read_explicit_context<'a>(
	reader: &mut SliceReader<'a>,
	number: TagNumber,
) -> Result<&'a [u8], VoteError> {
	let any = AnyRef::decode(reader)?;
	let expected = Tag::ContextSpecific { constructed: true, number };
	if any.tag() != expected {
		return Err(unexpected_tag(any.tag()));
	}
	Ok(any.value())
}

/// Read an `[N] IMPLICIT` primitive context-specific tag and return its
/// contents (the bytes of the implicitly-tagged OCTET STRING).
pub(crate) fn read_implicit_octet_context<'a>(
	reader: &mut SliceReader<'a>,
	number: TagNumber,
) -> Result<&'a [u8], VoteError> {
	let any = AnyRef::decode(reader)?;
	let expected = Tag::ContextSpecific { constructed: false, number };
	if any.tag() != expected {
		return Err(unexpected_tag(any.tag()));
	}
	Ok(any.value())
}

/// Peek at the upcoming tag without consuming any bytes.
pub(crate) fn peek_tag(reader: &SliceReader<'_>) -> Result<Tag, VoteError> {
	let mut probe = reader.clone();
	Ok(AnyRef::decode(&mut probe)?.tag())
}

// --- Account helpers ------------------------------------------------------

pub(crate) fn parse_account_octet(bytes: &[u8]) -> Result<AccountRef, VoteError> {
	let account =
		GenericAccount::from_hex(hex::encode(bytes)).map_err(|source: AccountError| VoteError::from(source))?;
	Ok(Arc::new(account))
}
