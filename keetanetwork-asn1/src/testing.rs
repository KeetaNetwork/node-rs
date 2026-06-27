//! Byte-level ASN.1 surgery helpers for downstream test suites.

use alloc::vec::Vec;

use der::asn1::AnyRef;
use der::{Decode, Encode, ErrorKind, Length, Reader, SliceReader, Tag, TagNumber, Tagged};

use crate::Asn1Error;

/// Encode `INTEGER 0` as a self-contained TLV. A convenient "obviously
/// wrong" stand-in when corrupting a slot that should carry something else.
pub fn integer_zero_tlv() -> Result<Vec<u8>, Asn1Error> {
	any_tlv(Tag::Integer, &[0x00])
}

/// Encode an `OCTET STRING` TLV with the supplied content.
pub fn octet_string_tlv(content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	any_tlv(Tag::OctetString, content)
}

/// Encode an empty `OCTET STRING` TLV.
pub fn empty_octet_string_tlv() -> Result<Vec<u8>, Asn1Error> {
	any_tlv(Tag::OctetString, &[])
}

/// Encode a SEQUENCE whose body is the concatenation of the supplied
/// pre-encoded TLV blobs.
pub fn sequence_tlv<I, B>(parts: I) -> Result<Vec<u8>, Asn1Error>
where
	I: IntoIterator<Item = B>,
	B: AsRef<[u8]>,
{
	join_with_tag(Tag::Sequence, parts)
}

/// Encode an `[N] EXPLICIT` constructed context-specific TLV whose body
/// is the concatenation of the supplied pre-encoded TLV blobs.
pub fn explicit_context_tlv<I, B>(number: u8, parts: I) -> Result<Vec<u8>, Asn1Error>
where
	I: IntoIterator<Item = B>,
	B: AsRef<[u8]>,
{
	let tag = Tag::ContextSpecific { constructed: true, number: TagNumber::new(number) };
	join_with_tag(tag, parts)
}

/// Decode every TLV inside `bytes` and return their owned encodings.
pub fn split_tlvs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Asn1Error> {
	let mut reader = SliceReader::new(bytes)?;
	let mut parts = Vec::new();
	while !reader.is_finished() {
		let element = AnyRef::decode(&mut reader)?;
		parts.push(element.to_der()?);
	}

	Ok(parts)
}

/// Split the TLV(s) inside a SEQUENCE into owned, individually-encoded
/// pieces. Given the bytes of `SEQUENCE { x, y, z }`, returns the bytes
/// of `[x, y, z]`.
pub fn split_sequence(bytes: &[u8]) -> Result<Vec<Vec<u8>>, Asn1Error> {
	let mut outer = SliceReader::new(bytes)?;
	let any = AnyRef::decode(&mut outer)?;
	if any.tag() != Tag::Sequence {
		return Err(unexpected_tag_err(any.tag()));
	}

	split_tlvs(any.value())
}

fn unexpected_tag_err(actual: Tag) -> Asn1Error {
	der::Error::new(ErrorKind::TagUnexpected { expected: Some(Tag::Sequence), actual }, Length::ZERO).into()
}

fn any_tlv(tag: Tag, content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

fn join_with_tag<I, B>(tag: Tag, parts: I) -> Result<Vec<u8>, Asn1Error>
where
	I: IntoIterator<Item = B>,
	B: AsRef<[u8]>,
{
	let mut content = Vec::new();
	for part in parts {
		content.extend_from_slice(part.as_ref());
	}

	any_tlv(tag, &content)
}
