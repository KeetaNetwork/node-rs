//! Versioned DER codec for blocks.
//!
//! The wire format is defined by the reference implementation:
//!
//! - V1: `SEQUENCE { 0, network, subnet|NULL, idempotent?, date, signer,
//!   account|NULL, previous, operations, signature? }`
//! - V2: `[1] EXPLICIT SEQUENCE { network, subnet?, idempotent?, date,
//!   purpose, account, signer(NULL|OCTET|multisig), previous, operations,
//!   signatures(OCTET | SEQUENCE OF OCTET)? }`
//!
//! All composite values are built from `der` primitives so tag and length
//! encoding is always canonical DER.

use std::sync::Arc;

use der::asn1::{AnyRef, Null, OctetStringRef, Utf8StringRef};
use der::{Decode, Encode, ErrorKind, Length, Reader, SliceReader, Tag, TagNumber, Tagged};
use keetanetwork_account::KeyPairType;
use keetanetwork_crypto::hash::BlockHash;
use num_bigint::BigInt;

use crate::account_util::{accounts_equal, parse_account_with_type};
use crate::amount::Amount;
use crate::block::{BlockData, BlockPurpose, BlockVersion, Signature, MAX_PARSE_SIGNER_DEPTH};
use crate::error::BlockError;
use crate::operation::Operation;
use crate::signer::{AccountRef, Signer};
use crate::time::BlockTime;

/// Context tag number of the V2 block wrapper.
const V2_TAG: TagNumber = TagNumber::N1;

pub(crate) fn unexpected_tag(actual: Tag) -> BlockError {
	der::Error::new(ErrorKind::TagUnexpected { expected: None, actual }, Length::ZERO).into()
}

// --- Encoding helpers -----------------------------------------------------

pub(crate) fn encode_octet(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), BlockError> {
	OctetStringRef::new(bytes)?.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_utf8(out: &mut Vec<u8>, value: &str) -> Result<(), BlockError> {
	Utf8StringRef::new(value)?.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_bigint(out: &mut Vec<u8>, value: &BigInt) -> Result<(), BlockError> {
	let bytes = value.to_signed_bytes_be();
	AnyRef::new(Tag::Integer, &bytes)?.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_null(out: &mut Vec<u8>) -> Result<(), BlockError> {
	Null.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_bool(out: &mut Vec<u8>, value: bool) -> Result<(), BlockError> {
	value.encode_to_vec(out)?;
	Ok(())
}

pub(crate) fn encode_account(out: &mut Vec<u8>, account: &AccountRef) -> Result<(), BlockError> {
	encode_octet(out, &account.to_public_key_with_type())
}

pub(crate) fn encode_time(out: &mut Vec<u8>, time: &BlockTime) -> Result<(), BlockError> {
	time.encode_to_vec(out)?;
	Ok(())
}

/// Wrap content bytes in a SEQUENCE TLV.
pub(crate) fn wrap_sequence(content: &[u8]) -> Result<Vec<u8>, BlockError> {
	Ok(AnyRef::new(Tag::Sequence, content)?.to_der()?)
}

/// Wrap content bytes in an `[N] EXPLICIT` constructed context tag.
pub(crate) fn wrap_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, BlockError> {
	let tag = Tag::ContextSpecific { constructed: true, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

// --- Decoding helpers -----------------------------------------------------

pub(crate) fn read_octet<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], BlockError> {
	Ok(OctetStringRef::decode(reader)?.as_bytes())
}

pub(crate) fn read_bigint(reader: &mut SliceReader<'_>) -> Result<BigInt, BlockError> {
	Ok(Amount::decode(reader)?.into())
}

pub(crate) fn read_utf8(reader: &mut SliceReader<'_>) -> Result<String, BlockError> {
	Ok(Utf8StringRef::decode(reader)?.as_str().to_string())
}

pub(crate) fn read_bool(reader: &mut SliceReader<'_>) -> Result<bool, BlockError> {
	Ok(bool::decode(reader)?)
}

pub(crate) fn read_null(reader: &mut SliceReader<'_>) -> Result<(), BlockError> {
	Null::decode(reader)?;
	Ok(())
}

pub(crate) fn read_account(reader: &mut SliceReader<'_>) -> Result<AccountRef, BlockError> {
	let bytes = read_octet(reader)?;
	Ok(Arc::new(parse_account_with_type(bytes)?))
}

pub(crate) fn read_block_hash(reader: &mut SliceReader<'_>) -> Result<BlockHash, BlockError> {
	let bytes = read_octet(reader)?;
	Ok(BlockHash::try_from(bytes)?)
}

/// Read a `SEQUENCE` and return its content bytes.
pub(crate) fn read_sequence<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], BlockError> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Sequence {
		return Err(unexpected_tag(any.tag()));
	}

	Ok(any.value())
}

// --- Multisig signer codec ------------------------------------------------

/// Encode a multisig signer tree iteratively (no function recursion).
///
/// Wire form per level: `SEQUENCE { OCTET address, SEQUENCE OF
/// (OCTET account | SEQUENCE nested) }`.
fn encode_multisig_signer(address: &AccountRef, signers: &[Signer]) -> Result<Vec<u8>, BlockError> {
	struct Frame<'a> {
		address: &'a AccountRef,
		children: &'a [Signer],
		child_index: usize,
		encoded_children: Vec<u8>,
	}

	let mut stack = vec![Frame { address, children: signers, child_index: 0, encoded_children: Vec::new() }];

	loop {
		let Some(top) = stack.last_mut() else {
			return Err(BlockError::MalformedSigner);
		};

		if let Some(child) = top.children.get(top.child_index) {
			top.child_index += 1;
			match child {
				Signer::Single(account) => {
					encode_account(&mut top.encoded_children, account)?;
				}
				Signer::Multisig { address, signers } => {
					stack.push(Frame { address, children: signers, child_index: 0, encoded_children: Vec::new() });
				}
			}
			continue;
		}

		let frame = stack.pop().ok_or(BlockError::MalformedSigner)?;
		let mut content = Vec::new();
		encode_account(&mut content, frame.address)?;
		content.extend_from_slice(&wrap_sequence(&frame.encoded_children)?);
		let container = wrap_sequence(&content)?;

		match stack.last_mut() {
			Some(parent) => parent.encoded_children.extend_from_slice(&container),
			None => return Ok(container),
		}
	}
}

/// Decode a multisig signer tree iteratively from the content bytes of its
/// outer SEQUENCE, enforcing the parse depth limit.
fn decode_multisig_signer(content: &[u8]) -> Result<Signer, BlockError> {
	struct Frame<'a> {
		address: AccountRef,
		reader: SliceReader<'a>,
		children: Vec<Signer>,
	}

	fn open_frame<'a>(content: &'a [u8]) -> Result<Frame<'a>, BlockError> {
		let mut reader = SliceReader::new(content)?;

		let address = read_account(&mut reader)?;
		if address.to_keypair_type() != KeyPairType::MULTISIG {
			return Err(BlockError::MalformedSigner);
		}

		let signers_content = read_sequence(&mut reader)?;
		if !reader.is_finished() {
			return Err(BlockError::MalformedSigner);
		}

		Ok(Frame { address, reader: SliceReader::new(signers_content)?, children: Vec::new() })
	}

	let mut stack = vec![open_frame(content)?];

	loop {
		let Some(top) = stack.last_mut() else {
			return Err(BlockError::MalformedSigner);
		};

		if !top.reader.is_finished() {
			match top.reader.peek_tag()? {
				Tag::OctetString => {
					let account = read_account(&mut top.reader)?;
					top.children.push(Signer::Single(account));
				}
				Tag::Sequence => {
					let nested_content = read_sequence(&mut top.reader)?;
					if stack.len() > MAX_PARSE_SIGNER_DEPTH {
						return Err(BlockError::MultisigSignerDepthExceeded {
							depth: stack.len() as u64,
							max: MAX_PARSE_SIGNER_DEPTH as u64,
						});
					}

					stack.push(open_frame(nested_content)?);
				}
				other => return Err(unexpected_tag(other)),
			}
			continue;
		}

		let frame = stack.pop().ok_or(BlockError::MalformedSigner)?;
		let signer = Signer::Multisig { address: frame.address, signers: frame.children };

		match stack.last_mut() {
			Some(parent) => parent.children.push(signer),
			None => return Ok(signer),
		}
	}
}

// --- Block codec ------------------------------------------------------------

/// Encode a block (signed when signatures are provided).
pub(crate) fn encode_block(data: &BlockData, signatures: Option<&[Signature]>) -> Result<Vec<u8>, BlockError> {
	match data.version {
		BlockVersion::V1 => encode_block_v1(data, signatures),
		BlockVersion::V2 => encode_block_v2(data, signatures),
	}
}

fn encode_operations(out: &mut Vec<u8>, operations: &[Operation]) -> Result<(), BlockError> {
	let mut content = Vec::new();
	for operation in operations {
		content.extend_from_slice(&operation.to_wire()?);
	}
	out.extend_from_slice(&wrap_sequence(&content)?);
	Ok(())
}

fn encode_block_v1(data: &BlockData, signatures: Option<&[Signature]>) -> Result<Vec<u8>, BlockError> {
	let Signer::Single(signer) = &data.signer else {
		return Err(BlockError::V1SingleSignerOnly);
	};

	let mut content = Vec::new();
	encode_bigint(&mut content, &BigInt::ZERO)?;
	encode_bigint(&mut content, &data.network)?;
	match &data.subnet {
		Some(subnet) => encode_bigint(&mut content, subnet)?,
		None => encode_null(&mut content)?,
	}
	if let Some(idempotent) = &data.idempotent {
		encode_octet(&mut content, idempotent)?;
	}
	encode_time(&mut content, &data.date)?;
	encode_account(&mut content, signer)?;
	if accounts_equal(&data.account, signer) {
		encode_null(&mut content)?;
	} else {
		encode_account(&mut content, &data.account)?;
	}
	encode_octet(&mut content, data.previous.as_bytes())?;
	encode_operations(&mut content, &data.operations)?;

	if let Some(signatures) = signatures {
		let [signature] = signatures else {
			return Err(BlockError::V1SingleSignerOnly);
		};
		encode_octet(&mut content, signature.as_ref())?;
	}

	wrap_sequence(&content)
}

fn encode_block_v2(data: &BlockData, signatures: Option<&[Signature]>) -> Result<Vec<u8>, BlockError> {
	let mut content = Vec::new();

	encode_bigint(&mut content, &data.network)?;

	if let Some(subnet) = &data.subnet {
		encode_bigint(&mut content, subnet)?;
	}
	if let Some(idempotent) = &data.idempotent {
		encode_octet(&mut content, idempotent)?;
	}

	encode_time(&mut content, &data.date)?;
	encode_bigint(&mut content, &data.purpose.to_bigint())?;
	encode_account(&mut content, &data.account)?;

	match &data.signer {
		Signer::Single(signer) => {
			if accounts_equal(signer, &data.account) {
				encode_null(&mut content)?;
			} else {
				encode_account(&mut content, signer)?;
			}
		}
		Signer::Multisig { address, signers } => {
			content.extend_from_slice(&encode_multisig_signer(address, signers)?);
		}
	}

	encode_octet(&mut content, data.previous.as_bytes())?;
	encode_operations(&mut content, &data.operations)?;

	if let Some(signatures) = signatures {
		match signatures {
			[] => return Err(BlockError::SignatureRequired),
			[signature] => encode_octet(&mut content, signature.as_ref())?,
			multiple => {
				let mut sequence = Vec::new();
				for signature in multiple {
					encode_octet(&mut sequence, signature.as_ref())?;
				}
				content.extend_from_slice(&wrap_sequence(&sequence)?);
			}
		}
	}

	wrap_context(V2_TAG, &wrap_sequence(&content)?)
}

/// Decode a block from its DER bytes.
pub(crate) fn decode_block(bytes: &[u8]) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	let mut reader = SliceReader::new(bytes)?;
	let any = AnyRef::decode(&mut reader)?;

	match any.tag() {
		Tag::Sequence => decode_block_v1(any.value()),
		Tag::ContextSpecific { constructed: true, number } if number == V2_TAG => {
			let mut inner = SliceReader::new(any.value())?;
			let content = read_sequence(&mut inner)?;
			if !inner.is_finished() {
				return Err(BlockError::InvalidVersion);
			}

			decode_block_v2(content)
		}
		_ => Err(BlockError::InvalidVersion),
	}
}

fn decode_operations(reader: &mut SliceReader<'_>) -> Result<Vec<Operation>, BlockError> {
	let content = read_sequence(reader)?;
	let mut inner = SliceReader::new(content)?;

	let mut operations = Vec::new();
	while !inner.is_finished() {
		operations.push(Operation::from_wire(&mut inner)?);
	}

	Ok(operations)
}

fn decode_block_v1(content: &[u8]) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	let mut reader = SliceReader::new(content)?;

	let version = read_bigint(&mut reader)?;
	if version != BigInt::ZERO {
		return Err(BlockError::InvalidVersion);
	}

	let network = read_bigint(&mut reader)?;

	let subnet = match reader.peek_tag()? {
		Tag::Integer => Some(read_bigint(&mut reader)?),
		Tag::Null => {
			read_null(&mut reader)?;
			None
		}
		other => return Err(unexpected_tag(other)),
	};

	let idempotent = if reader.peek_tag()? == Tag::OctetString {
		Some(read_octet(&mut reader)?.to_vec())
	} else {
		None
	};

	let date = BlockTime::decode(&mut reader)?;
	let signer = read_account(&mut reader)?;

	let account = if reader.peek_tag()? == Tag::Null {
		read_null(&mut reader)?;
		signer.clone()
	} else {
		let account = read_account(&mut reader)?;
		if accounts_equal(&account, &signer) {
			return Err(BlockError::RedundantAccountField);
		}
		account
	};

	let previous = read_block_hash(&mut reader)?;
	let operations = decode_operations(&mut reader)?;

	let signatures = if reader.is_finished() {
		None
	} else {
		let signature = Signature::try_from(read_octet(&mut reader)?)?;
		Some(vec![signature])
	};

	if !reader.is_finished() {
		return Err(BlockError::RecalculatedBytesMismatch);
	}

	let data = BlockData {
		version: BlockVersion::V1,
		purpose: BlockPurpose::Generic,
		network,
		subnet,
		idempotent,
		date,
		account,
		signer: Signer::Single(signer),
		previous,
		operations,
	};

	Ok((data, signatures))
}

fn decode_block_v2(content: &[u8]) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	let mut reader = SliceReader::new(content)?;

	let network = read_bigint(&mut reader)?;

	let subnet = if reader.peek_tag()? == Tag::Integer {
		Some(read_bigint(&mut reader)?)
	} else {
		None
	};

	let idempotent = if reader.peek_tag()? == Tag::OctetString {
		Some(read_octet(&mut reader)?.to_vec())
	} else {
		None
	};

	let date = BlockTime::decode(&mut reader)?;
	let purpose = BlockPurpose::try_from(&read_bigint(&mut reader)?)?;
	let account = read_account(&mut reader)?;

	let signer = match reader.peek_tag()? {
		Tag::Null => {
			read_null(&mut reader)?;
			Signer::Single(account.clone())
		}
		Tag::OctetString => {
			let signer = read_account(&mut reader)?;
			if accounts_equal(&signer, &account) {
				return Err(BlockError::RedundantAccountField);
			}
			Signer::Single(signer)
		}
		Tag::Sequence => decode_multisig_signer(read_sequence(&mut reader)?)?,
		other => return Err(unexpected_tag(other)),
	};

	let previous = read_block_hash(&mut reader)?;
	let operations = decode_operations(&mut reader)?;

	let signatures = if reader.is_finished() {
		None
	} else {
		match reader.peek_tag()? {
			Tag::OctetString => {
				let signature = Signature::try_from(read_octet(&mut reader)?)?;
				Some(vec![signature])
			}
			Tag::Sequence => {
				let content = read_sequence(&mut reader)?;
				let mut inner = SliceReader::new(content)?;
				let mut signatures = Vec::new();
				while !inner.is_finished() {
					signatures.push(Signature::try_from(read_octet(&mut inner)?)?);
				}

				if signatures.len() <= 1 {
					return Err(BlockError::InvalidSignatureSequence);
				}

				Some(signatures)
			}
			other => return Err(unexpected_tag(other)),
		}
	};

	if !reader.is_finished() {
		return Err(BlockError::RecalculatedBytesMismatch);
	}

	let data = BlockData {
		version: BlockVersion::V2,
		purpose,
		network,
		subnet,
		idempotent,
		date,
		account,
		signer,
		previous,
		operations,
	};

	Ok((data, signatures))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_wrap_sequence_empty() {
		assert_eq!(wrap_sequence(&[]).unwrap(), [0x30, 0x00]);
	}

	#[test]
	fn test_wrap_context_tag() {
		let inner = wrap_sequence(&[]).unwrap();
		let wrapped = wrap_context(V2_TAG, &inner).unwrap();
		assert_eq!(wrapped, [0xA1, 0x02, 0x30, 0x00]);
	}

	#[test]
	fn test_encode_helpers() {
		let mut out = Vec::new();
		encode_bigint(&mut out, &BigInt::from(0x80u32)).unwrap();
		encode_null(&mut out).unwrap();
		encode_bool(&mut out, true).unwrap();
		encode_octet(&mut out, &[0xAB]).unwrap();
		assert_eq!(out, [0x02, 0x02, 0x00, 0x80, 0x05, 0x00, 0x01, 0x01, 0xFF, 0x04, 0x01, 0xAB]);
	}

	#[test]
	fn test_read_helpers_roundtrip() {
		let mut out = Vec::new();
		encode_bigint(&mut out, &BigInt::from(42u8)).unwrap();
		encode_utf8(&mut out, "hi").unwrap();
		encode_bool(&mut out, false).unwrap();

		let mut reader = SliceReader::new(&out).unwrap();
		assert_eq!(read_bigint(&mut reader).unwrap(), BigInt::from(42u8));
		assert_eq!(read_utf8(&mut reader).unwrap(), "hi");
		assert!(!read_bool(&mut reader).unwrap());
		assert!(reader.is_finished());
	}
}
