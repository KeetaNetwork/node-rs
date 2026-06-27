//! `der`-backed encode/decode for the public neutral block types.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::block::types::{
	Block, BlockV1, BlockV2, BlockV2Body, CertificatePrincipal, CreateIdentifierOp, IntegerOrNull,
	IntermediateCertificates, ManageCertificateOp, ModifyPermissionsOp, ModifyPermissionsPrincipal, MultisigArguments,
	MultisigSigner, OctetStringOrNull, Operation, Permissions, PermissionsOrNull, ReceiveOp, SendOp, SetInfoOp,
	SetRepOp, Signatures, Signer, TokenAdminModifyBalanceOp, TokenAdminSupplyOp,
};
use crate::Asn1Error;
use crate::Asn1Time;
use ::der::asn1::{AnyRef, Null, OctetStringRef, Utf8StringRef};
use ::der::{Decode, Encode, ErrorKind, Length, Reader, SliceReader, Tag, TagNumber, Tagged};
use num_bigint::BigInt;

// --- Transport constants ------------------------------------------------------

/// Context tag number of the V2 block wrapper.
const V2_TAG: TagNumber = TagNumber::N1;
/// Context tag of a certificate principal in MODIFY_PERMISSIONS.
const CERTIFICATE_PRINCIPAL_TAG: TagNumber = TagNumber::N1;
/// Context tag of multisig create arguments (the MULTISIG key type value).
const MULTISIG_ARGUMENTS_TAG: TagNumber = TagNumber::N7;

fn unexpected_tag(actual: Tag) -> Asn1Error {
	Asn1Error::DerError { source: ::der::Error::new(ErrorKind::TagUnexpected { expected: None, actual }, Length::ZERO) }
}

fn invalid_block() -> Asn1Error {
	Asn1Error::InvalidBlockVersion
}

// --- Encoding helpers ----------------------------------------------------

fn encode_octet(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Asn1Error> {
	OctetStringRef::new(bytes)?.encode_to_vec(out)?;
	Ok(())
}

fn encode_utf8(out: &mut Vec<u8>, value: &str) -> Result<(), Asn1Error> {
	Utf8StringRef::new(value)?.encode_to_vec(out)?;
	Ok(())
}

fn encode_bigint(out: &mut Vec<u8>, value: &BigInt) -> Result<(), Asn1Error> {
	let bytes = value.to_signed_bytes_be();
	AnyRef::new(Tag::Integer, &bytes)?.encode_to_vec(out)?;
	Ok(())
}

fn encode_null(out: &mut Vec<u8>) -> Result<(), Asn1Error> {
	Null.encode_to_vec(out)?;
	Ok(())
}

fn encode_bool(out: &mut Vec<u8>, value: bool) -> Result<(), Asn1Error> {
	value.encode_to_vec(out)?;
	Ok(())
}

fn encode_time(out: &mut Vec<u8>, time: &Asn1Time) -> Result<(), Asn1Error> {
	time.encode_to_vec(out)?;
	Ok(())
}

fn wrap_sequence(content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	Ok(AnyRef::new(Tag::Sequence, content)?.to_der()?)
}

fn wrap_context(number: TagNumber, content: &[u8]) -> Result<Vec<u8>, Asn1Error> {
	let tag = Tag::ContextSpecific { constructed: true, number };
	Ok(AnyRef::new(tag, content)?.to_der()?)
}

// --- Decoding helpers ----------------------------------------------------

fn read_octet<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	Ok(OctetStringRef::decode(reader)?.as_bytes())
}

fn read_bigint(reader: &mut SliceReader<'_>) -> Result<BigInt, Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Integer {
		return Err(unexpected_tag(any.tag()));
	}

	Ok(BigInt::from_signed_bytes_be(any.value()))
}

fn read_utf8(reader: &mut SliceReader<'_>) -> Result<String, Asn1Error> {
	Ok(Utf8StringRef::decode(reader)?.as_str().to_string())
}

fn read_bool(reader: &mut SliceReader<'_>) -> Result<bool, Asn1Error> {
	Ok(bool::decode(reader)?)
}

fn read_null(reader: &mut SliceReader<'_>) -> Result<(), Asn1Error> {
	Null::decode(reader)?;
	Ok(())
}

fn read_time(reader: &mut SliceReader<'_>) -> Result<Asn1Time, Asn1Error> {
	Ok(Asn1Time::decode(reader)?)
}

fn read_sequence<'a>(reader: &mut SliceReader<'a>) -> Result<&'a [u8], Asn1Error> {
	let any = AnyRef::decode(reader)?;
	if any.tag() != Tag::Sequence {
		return Err(unexpected_tag(any.tag()));
	}

	Ok(any.value())
}

// --- Top-level entry points ----------------------------------------------

pub(super) fn encode_v1(value: &BlockV1) -> Result<Vec<u8>, Asn1Error> {
	let mut content = Vec::new();
	encode_bigint(&mut content, &value.version)?;
	encode_bigint(&mut content, &value.network)?;
	encode_integer_or_null(&mut content, &value.subnet)?;
	if let Some(idempotent) = &value.idempotent {
		encode_octet(&mut content, idempotent)?;
	}
	encode_time(&mut content, &value.date)?;
	encode_octet(&mut content, &value.signer)?;
	encode_octet_or_null(&mut content, &value.account)?;
	encode_octet(&mut content, &value.previous)?;
	encode_operations(&mut content, &value.operations)?;
	if let Some(signature) = &value.signature {
		encode_octet(&mut content, signature)?;
	}
	wrap_sequence(&content)
}

pub(super) fn encode_v2(value: &BlockV2) -> Result<Vec<u8>, Asn1Error> {
	let body = &value.0;
	let mut content = Vec::new();
	encode_bigint(&mut content, &body.network)?;
	if let Some(subnet) = &body.subnet {
		encode_bigint(&mut content, subnet)?;
	}
	if let Some(idempotent) = &body.idempotent {
		encode_octet(&mut content, idempotent)?;
	}
	encode_time(&mut content, &body.date)?;
	encode_bigint(&mut content, &body.purpose)?;
	encode_octet(&mut content, &body.account)?;
	encode_signer(&mut content, &body.signer)?;
	encode_octet(&mut content, &body.previous)?;
	encode_operations(&mut content, &body.operations)?;
	if let Some(signatures) = &body.signatures {
		encode_signatures(&mut content, signatures)?;
	}

	wrap_context(V2_TAG, &wrap_sequence(&content)?)
}

#[allow(dead_code)]
pub(super) fn encode_block(value: &Block) -> Result<Vec<u8>, Asn1Error> {
	match value {
		Block::V1(v1) => encode_v1(v1),
		Block::V2(v2) => encode_v2(v2),
	}
}

pub(super) fn decode_v1(bytes: &[u8]) -> Result<BlockV1, Asn1Error> {
	let mut outer = SliceReader::new(bytes)?;
	let any = AnyRef::decode(&mut outer)?;
	if any.tag() != Tag::Sequence {
		return Err(invalid_block());
	}

	if !outer.is_finished() {
		return Err(invalid_block());
	}

	let mut reader = SliceReader::new(any.value())?;
	let version = read_bigint(&mut reader)?;
	let network = read_bigint(&mut reader)?;
	let subnet = decode_integer_or_null(&mut reader)?;

	let idempotent = if reader.peek_tag()? == Tag::OctetString {
		Some(read_octet(&mut reader)?.to_vec())
	} else {
		None
	};

	let date = read_time(&mut reader)?;
	let signer = read_octet(&mut reader)?.to_vec();
	let account = decode_octet_or_null(&mut reader)?;
	let previous = read_octet(&mut reader)?.to_vec();
	let operations = decode_operations(&mut reader)?;

	let signature = if reader.is_finished() {
		None
	} else {
		Some(read_octet(&mut reader)?.to_vec())
	};

	if !reader.is_finished() {
		return Err(invalid_block());
	}

	Ok(BlockV1 { version, network, subnet, idempotent, date, signer, account, previous, operations, signature })
}

pub(super) fn decode_v2(bytes: &[u8]) -> Result<BlockV2, Asn1Error> {
	let mut outer = SliceReader::new(bytes)?;
	let any = AnyRef::decode(&mut outer)?;
	let Tag::ContextSpecific { constructed: true, number } = any.tag() else {
		return Err(invalid_block());
	};

	if number != V2_TAG {
		return Err(invalid_block());
	}

	if !outer.is_finished() {
		return Err(invalid_block());
	}

	let mut wrapper = SliceReader::new(any.value())?;
	let body = read_sequence(&mut wrapper)?;
	if !wrapper.is_finished() {
		return Err(invalid_block());
	}

	let mut reader = SliceReader::new(body)?;
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

	let date = read_time(&mut reader)?;
	let purpose = read_bigint(&mut reader)?;
	let account = read_octet(&mut reader)?.to_vec();
	let signer = decode_signer(&mut reader)?;
	let previous = read_octet(&mut reader)?.to_vec();
	let operations = decode_operations(&mut reader)?;

	let signatures = if reader.is_finished() {
		None
	} else {
		Some(decode_signatures(&mut reader)?)
	};

	if !reader.is_finished() {
		return Err(invalid_block());
	}

	Ok(BlockV2(BlockV2Body {
		network,
		subnet,
		idempotent,
		date,
		purpose,
		account,
		signer,
		previous,
		operations,
		signatures,
	}))
}

#[allow(dead_code)]
pub(super) fn decode_block(bytes: &[u8]) -> Result<Block, Asn1Error> {
	match bytes.first() {
		Some(0x30) => decode_v1(bytes).map(Block::V1),
		Some(0xA1) => decode_v2(bytes).map(Block::V2),
		_ => Err(invalid_block()),
	}
}

// --- IntegerOrNull / OctetStringOrNull -----------------------------------

fn encode_integer_or_null(out: &mut Vec<u8>, value: &IntegerOrNull) -> Result<(), Asn1Error> {
	match value {
		IntegerOrNull::Value(integer) => encode_bigint(out, integer),
		IntegerOrNull::Null => encode_null(out),
	}
}

fn decode_integer_or_null(reader: &mut SliceReader<'_>) -> Result<IntegerOrNull, Asn1Error> {
	match reader.peek_tag()? {
		Tag::Integer => Ok(IntegerOrNull::Value(read_bigint(reader)?)),
		Tag::Null => {
			read_null(reader)?;
			Ok(IntegerOrNull::Null)
		}
		other => Err(unexpected_tag(other)),
	}
}

fn encode_octet_or_null(out: &mut Vec<u8>, value: &OctetStringOrNull) -> Result<(), Asn1Error> {
	match value {
		OctetStringOrNull::Value(bytes) => encode_octet(out, bytes),
		OctetStringOrNull::Null => encode_null(out),
	}
}

fn decode_octet_or_null(reader: &mut SliceReader<'_>) -> Result<OctetStringOrNull, Asn1Error> {
	match reader.peek_tag()? {
		Tag::OctetString => Ok(OctetStringOrNull::Value(read_octet(reader)?.to_vec())),
		Tag::Null => {
			read_null(reader)?;
			Ok(OctetStringOrNull::Null)
		}
		other => Err(unexpected_tag(other)),
	}
}

// --- Signer --------------------------------------------------------------

fn encode_signer(out: &mut Vec<u8>, value: &Signer) -> Result<(), Asn1Error> {
	match value {
		Signer::Empty => encode_null(out),
		Signer::Single(bytes) => encode_octet(out, bytes),
		Signer::Multisig(multi) => {
			out.extend_from_slice(&encode_multisig_signer(multi)?);
			Ok(())
		}
	}
}

fn decode_signer(reader: &mut SliceReader<'_>) -> Result<Signer, Asn1Error> {
	match reader.peek_tag()? {
		Tag::Null => {
			read_null(reader)?;
			Ok(Signer::Empty)
		}
		Tag::OctetString => Ok(Signer::Single(read_octet(reader)?.to_vec())),
		Tag::Sequence => {
			let content = read_sequence(reader)?;
			Ok(Signer::Multisig(decode_multisig_signer(content)?))
		}
		other => Err(unexpected_tag(other)),
	}
}

/// Encode a multisig signer tree iteratively (no function recursion).
///
/// Transport form per level: `SEQUENCE { OCTET address, SEQUENCE OF (OCTET account
/// | SEQUENCE nested) }`.
fn encode_multisig_signer(value: &MultisigSigner) -> Result<Vec<u8>, Asn1Error> {
	struct Frame<'a> {
		address: &'a [u8],
		children: &'a [Signer],
		child_index: usize,
		encoded_children: Vec<u8>,
	}

	let mut stack = vec![Frame {
		address: value.address.as_slice(),
		children: value.signers.as_slice(),
		child_index: 0,
		encoded_children: Vec::new(),
	}];

	loop {
		let Some(top) = stack.last_mut() else {
			return Err(invalid_block());
		};

		if let Some(child) = top.children.get(top.child_index) {
			top.child_index += 1;
			match child {
				Signer::Empty => return Err(invalid_block()),
				Signer::Single(account) => encode_octet(&mut top.encoded_children, account)?,
				Signer::Multisig(nested) => {
					stack.push(Frame {
						address: nested.address.as_slice(),
						children: nested.signers.as_slice(),
						child_index: 0,
						encoded_children: Vec::new(),
					});
				}
			}
			continue;
		}

		let frame = stack.pop().ok_or_else(invalid_block)?;
		let mut content = Vec::new();
		encode_octet(&mut content, frame.address)?;
		content.extend_from_slice(&wrap_sequence(&frame.encoded_children)?);
		let container = wrap_sequence(&content)?;

		match stack.last_mut() {
			Some(parent) => parent.encoded_children.extend_from_slice(&container),
			None => return Ok(container),
		}
	}
}

/// Decode a multisig signer tree iteratively from the content bytes of its
/// outer SEQUENCE.
fn decode_multisig_signer(content: &[u8]) -> Result<MultisigSigner, Asn1Error> {
	struct Frame<'a> {
		address: Vec<u8>,
		reader: SliceReader<'a>,
		children: Vec<Signer>,
	}

	fn open_frame(content: &[u8]) -> Result<Frame<'_>, Asn1Error> {
		let mut reader = SliceReader::new(content)?;

		let address = read_octet(&mut reader)?.to_vec();

		let signers_content = read_sequence(&mut reader)?;
		if !reader.is_finished() {
			return Err(invalid_block());
		}

		Ok(Frame { address, reader: SliceReader::new(signers_content)?, children: Vec::new() })
	}

	let mut stack = vec![open_frame(content)?];

	loop {
		let Some(top) = stack.last_mut() else {
			return Err(invalid_block());
		};

		if !top.reader.is_finished() {
			match top.reader.peek_tag()? {
				Tag::OctetString => {
					let account = read_octet(&mut top.reader)?.to_vec();
					top.children.push(Signer::Single(account));
				}
				Tag::Sequence => {
					let nested_content = read_sequence(&mut top.reader)?;
					stack.push(open_frame(nested_content)?);
				}
				other => return Err(unexpected_tag(other)),
			}
			continue;
		}

		let frame = stack.pop().ok_or_else(invalid_block)?;
		let multi = MultisigSigner { address: frame.address, signers: frame.children };

		match stack.last_mut() {
			Some(parent) => parent.children.push(Signer::Multisig(multi)),
			None => return Ok(multi),
		}
	}
}

// --- Signatures ----------------------------------------------------------

fn encode_signatures(out: &mut Vec<u8>, value: &Signatures) -> Result<(), Asn1Error> {
	match value {
		Signatures::Single(bytes) => encode_octet(out, bytes),
		Signatures::Multiple(items) => {
			let mut content = Vec::new();
			for bytes in items {
				encode_octet(&mut content, bytes)?;
			}
			out.extend_from_slice(&wrap_sequence(&content)?);
			Ok(())
		}
	}
}

fn decode_signatures(reader: &mut SliceReader<'_>) -> Result<Signatures, Asn1Error> {
	match reader.peek_tag()? {
		Tag::OctetString => Ok(Signatures::Single(read_octet(reader)?.to_vec())),
		Tag::Sequence => {
			let content = read_sequence(reader)?;
			let mut inner = SliceReader::new(content)?;
			let mut items = Vec::new();
			while !inner.is_finished() {
				items.push(read_octet(&mut inner)?.to_vec());
			}
			Ok(Signatures::Multiple(items))
		}
		other => Err(unexpected_tag(other)),
	}
}

// --- Operations ----------------------------------------------------------

fn encode_operations(out: &mut Vec<u8>, operations: &[Operation]) -> Result<(), Asn1Error> {
	let mut content = Vec::new();
	for operation in operations {
		content.extend_from_slice(&encode_operation(operation)?);
	}
	out.extend_from_slice(&wrap_sequence(&content)?);
	Ok(())
}

fn decode_operations(reader: &mut SliceReader<'_>) -> Result<Vec<Operation>, Asn1Error> {
	let content = read_sequence(reader)?;
	let mut inner = SliceReader::new(content)?;

	let mut operations = Vec::new();
	while !inner.is_finished() {
		operations.push(decode_operation(&mut inner)?);
	}

	Ok(operations)
}

fn operation_tag(operation: &Operation) -> TagNumber {
	match operation {
		Operation::Send(_) => TagNumber::N0,
		Operation::SetRep(_) => TagNumber::N1,
		Operation::SetInfo(_) => TagNumber::N2,
		Operation::ModifyPermissions(_) => TagNumber::N3,
		Operation::CreateIdentifier(_) => TagNumber::N4,
		Operation::TokenAdminSupply(_) => TagNumber::N5,
		Operation::TokenAdminModifyBalance(_) => TagNumber::N6,
		Operation::Receive(_) => TagNumber::N7,
		Operation::ManageCertificate(_) => TagNumber::N8,
	}
}

fn encode_operation(operation: &Operation) -> Result<Vec<u8>, Asn1Error> {
	let mut fields = Vec::new();
	match operation {
		Operation::Send(op) => encode_send(&mut fields, op)?,
		Operation::SetRep(op) => encode_set_rep(&mut fields, op)?,
		Operation::SetInfo(op) => encode_set_info(&mut fields, op)?,
		Operation::ModifyPermissions(op) => encode_modify_permissions(&mut fields, op)?,
		Operation::CreateIdentifier(op) => encode_create_identifier(&mut fields, op)?,
		Operation::TokenAdminSupply(op) => encode_token_admin_supply(&mut fields, op)?,
		Operation::TokenAdminModifyBalance(op) => encode_token_admin_modify_balance(&mut fields, op)?,
		Operation::Receive(op) => encode_receive(&mut fields, op)?,
		Operation::ManageCertificate(op) => encode_manage_certificate(&mut fields, op)?,
	}
	wrap_context(operation_tag(operation), &wrap_sequence(&fields)?)
}

fn decode_operation(reader: &mut SliceReader<'_>) -> Result<Operation, Asn1Error> {
	let any = AnyRef::decode(reader)?;
	let Tag::ContextSpecific { constructed: true, number } = any.tag() else {
		return Err(invalid_block());
	};

	let mut outer = SliceReader::new(any.value())?;
	let content = read_sequence(&mut outer)?;
	if !outer.is_finished() {
		return Err(invalid_block());
	}

	let mut fields = SliceReader::new(content)?;

	let operation = match number.value() {
		0 => Operation::Send(decode_send(&mut fields)?),
		1 => Operation::SetRep(decode_set_rep(&mut fields)?),
		2 => Operation::SetInfo(decode_set_info(&mut fields)?),
		3 => Operation::ModifyPermissions(decode_modify_permissions(&mut fields)?),
		4 => Operation::CreateIdentifier(decode_create_identifier(&mut fields)?),
		5 => Operation::TokenAdminSupply(decode_token_admin_supply(&mut fields)?),
		6 => Operation::TokenAdminModifyBalance(decode_token_admin_modify_balance(&mut fields)?),
		7 => Operation::Receive(decode_receive(&mut fields)?),
		8 => Operation::ManageCertificate(decode_manage_certificate(&mut fields)?),
		_ => return Err(invalid_block()),
	};

	if !fields.is_finished() {
		return Err(invalid_block());
	}

	Ok(operation)
}

// --- Operation field codecs ---------------------------------------------

fn encode_send(out: &mut Vec<u8>, op: &SendOp) -> Result<(), Asn1Error> {
	encode_octet(out, &op.to)?;
	encode_bigint(out, &op.amount)?;
	encode_octet(out, &op.token)?;
	if let Some(external) = &op.external {
		encode_utf8(out, external)?;
	}
	Ok(())
}

fn decode_send(reader: &mut SliceReader<'_>) -> Result<SendOp, Asn1Error> {
	let to = read_octet(reader)?.to_vec();
	let amount = read_bigint(reader)?;
	let token = read_octet(reader)?.to_vec();
	let external = if reader.is_finished() {
		None
	} else {
		Some(read_utf8(reader)?)
	};

	Ok(SendOp { to, amount, token, external })
}

fn encode_set_rep(out: &mut Vec<u8>, op: &SetRepOp) -> Result<(), Asn1Error> {
	encode_octet(out, &op.to)
}

fn decode_set_rep(reader: &mut SliceReader<'_>) -> Result<SetRepOp, Asn1Error> {
	Ok(SetRepOp { to: read_octet(reader)?.to_vec() })
}

fn encode_set_info(out: &mut Vec<u8>, op: &SetInfoOp) -> Result<(), Asn1Error> {
	encode_utf8(out, &op.name)?;
	encode_utf8(out, &op.description)?;
	encode_utf8(out, &op.metadata)?;
	if let Some(default_permission) = &op.default_permission {
		encode_permissions(out, default_permission)?;
	}
	Ok(())
}

fn decode_set_info(reader: &mut SliceReader<'_>) -> Result<SetInfoOp, Asn1Error> {
	let name = read_utf8(reader)?;
	let description = read_utf8(reader)?;
	let metadata = read_utf8(reader)?;
	let default_permission = if reader.is_finished() {
		None
	} else {
		Some(read_permissions(reader)?)
	};

	Ok(SetInfoOp { name, description, metadata, default_permission })
}

fn encode_modify_permissions(out: &mut Vec<u8>, op: &ModifyPermissionsOp) -> Result<(), Asn1Error> {
	match &op.principal {
		ModifyPermissionsPrincipal::Account(bytes) => encode_octet(out, bytes)?,
		ModifyPermissionsPrincipal::Certificate(certificate) => {
			let mut content = Vec::new();
			encode_octet(&mut content, &certificate.hash)?;
			encode_octet(&mut content, &certificate.account)?;
			let sequence = wrap_sequence(&content)?;
			out.extend_from_slice(&wrap_context(CERTIFICATE_PRINCIPAL_TAG, &sequence)?);
		}
	}

	encode_bigint(out, &op.method)?;

	match &op.permissions {
		PermissionsOrNull::Permissions(permissions) => encode_permissions(out, permissions)?,
		PermissionsOrNull::Null => encode_null(out)?,
	}

	if let Some(target) = &op.target {
		encode_octet(out, target)?;
	}

	Ok(())
}

fn decode_modify_permissions(reader: &mut SliceReader<'_>) -> Result<ModifyPermissionsOp, Asn1Error> {
	let principal = match reader.peek_tag()? {
		Tag::OctetString => ModifyPermissionsPrincipal::Account(read_octet(reader)?.to_vec()),
		Tag::ContextSpecific { constructed: true, number } if number == CERTIFICATE_PRINCIPAL_TAG => {
			let any = AnyRef::decode(reader)?;
			let mut outer = SliceReader::new(any.value())?;
			let content = read_sequence(&mut outer)?;
			if !outer.is_finished() {
				return Err(invalid_block());
			}

			let mut inner = SliceReader::new(content)?;
			let hash = read_octet(&mut inner)?.to_vec();
			let account = read_octet(&mut inner)?.to_vec();
			if !inner.is_finished() {
				return Err(invalid_block());
			}

			ModifyPermissionsPrincipal::Certificate(CertificatePrincipal { hash, account })
		}
		other => return Err(unexpected_tag(other)),
	};

	let method = read_bigint(reader)?;

	let permissions = match reader.peek_tag()? {
		Tag::Null => {
			read_null(reader)?;
			PermissionsOrNull::Null
		}
		Tag::Sequence => PermissionsOrNull::Permissions(read_permissions(reader)?),
		other => return Err(unexpected_tag(other)),
	};

	let target = if reader.is_finished() {
		None
	} else {
		Some(read_octet(reader)?.to_vec())
	};

	Ok(ModifyPermissionsOp { principal, method, permissions, target })
}

fn encode_create_identifier(out: &mut Vec<u8>, op: &CreateIdentifierOp) -> Result<(), Asn1Error> {
	encode_octet(out, &op.identifier)?;

	if let Some(arguments) = &op.multisig {
		let mut signers = Vec::new();
		for signer in &arguments.signers {
			encode_octet(&mut signers, signer)?;
		}

		let mut content = wrap_sequence(&signers)?;
		encode_bigint(&mut content, &arguments.quorum)?;
		let sequence = wrap_sequence(&content)?;
		out.extend_from_slice(&wrap_context(MULTISIG_ARGUMENTS_TAG, &sequence)?);
	}

	Ok(())
}

fn decode_create_identifier(reader: &mut SliceReader<'_>) -> Result<CreateIdentifierOp, Asn1Error> {
	let identifier = read_octet(reader)?.to_vec();

	let multisig = if reader.is_finished() {
		None
	} else {
		match reader.peek_tag()? {
			Tag::ContextSpecific { constructed: true, number } if number == MULTISIG_ARGUMENTS_TAG => {
				let any = AnyRef::decode(reader)?;
				let mut outer = SliceReader::new(any.value())?;
				let content = read_sequence(&mut outer)?;
				if !outer.is_finished() {
					return Err(invalid_block());
				}

				let mut inner = SliceReader::new(content)?;
				let signers_content = read_sequence(&mut inner)?;
				let mut signers_reader = SliceReader::new(signers_content)?;
				let mut signers = Vec::new();
				while !signers_reader.is_finished() {
					signers.push(read_octet(&mut signers_reader)?.to_vec());
				}

				let quorum = read_bigint(&mut inner)?;
				if !inner.is_finished() {
					return Err(invalid_block());
				}

				Some(MultisigArguments { signers, quorum })
			}
			other => return Err(unexpected_tag(other)),
		}
	};

	Ok(CreateIdentifierOp { identifier, multisig })
}

fn encode_token_admin_supply(out: &mut Vec<u8>, op: &TokenAdminSupplyOp) -> Result<(), Asn1Error> {
	encode_bigint(out, &op.amount)?;
	encode_bigint(out, &op.method)
}

fn decode_token_admin_supply(reader: &mut SliceReader<'_>) -> Result<TokenAdminSupplyOp, Asn1Error> {
	let amount = read_bigint(reader)?;
	let method = read_bigint(reader)?;
	Ok(TokenAdminSupplyOp { amount, method })
}

fn encode_token_admin_modify_balance(out: &mut Vec<u8>, op: &TokenAdminModifyBalanceOp) -> Result<(), Asn1Error> {
	encode_octet(out, &op.token)?;
	encode_bigint(out, &op.amount)?;
	encode_bigint(out, &op.method)
}

fn decode_token_admin_modify_balance(reader: &mut SliceReader<'_>) -> Result<TokenAdminModifyBalanceOp, Asn1Error> {
	let token = read_octet(reader)?.to_vec();
	let amount = read_bigint(reader)?;
	let method = read_bigint(reader)?;
	Ok(TokenAdminModifyBalanceOp { token, amount, method })
}

fn encode_receive(out: &mut Vec<u8>, op: &ReceiveOp) -> Result<(), Asn1Error> {
	encode_bigint(out, &op.amount)?;
	encode_octet(out, &op.token)?;
	encode_octet(out, &op.from)?;
	encode_bool(out, op.exact)?;
	if let Some(forward) = &op.forward {
		encode_octet(out, forward)?;
	}
	Ok(())
}

fn decode_receive(reader: &mut SliceReader<'_>) -> Result<ReceiveOp, Asn1Error> {
	let amount = read_bigint(reader)?;
	let token = read_octet(reader)?.to_vec();
	let from = read_octet(reader)?.to_vec();
	let exact = read_bool(reader)?;
	let forward = if reader.is_finished() {
		None
	} else {
		Some(read_octet(reader)?.to_vec())
	};

	Ok(ReceiveOp { amount, token, from, exact, forward })
}

fn encode_manage_certificate(out: &mut Vec<u8>, op: &ManageCertificateOp) -> Result<(), Asn1Error> {
	encode_bigint(out, &op.method)?;
	encode_octet(out, &op.certificate_or_hash)?;

	match &op.intermediate_certificates {
		None => {}
		Some(IntermediateCertificates::Null) => encode_null(out)?,
		Some(IntermediateCertificates::Bundle(certificates)) => {
			let mut content = Vec::new();
			for certificate in certificates {
				encode_octet(&mut content, certificate)?;
			}
			out.extend_from_slice(&wrap_sequence(&content)?);
		}
	}

	Ok(())
}

fn decode_manage_certificate(reader: &mut SliceReader<'_>) -> Result<ManageCertificateOp, Asn1Error> {
	let method = read_bigint(reader)?;
	let certificate_or_hash = read_octet(reader)?.to_vec();

	let intermediate_certificates = if reader.is_finished() {
		None
	} else {
		match reader.peek_tag()? {
			Tag::Null => {
				read_null(reader)?;
				Some(IntermediateCertificates::Null)
			}
			Tag::Sequence => {
				let content = read_sequence(reader)?;
				let mut inner = SliceReader::new(content)?;
				let mut certificates = Vec::new();
				while !inner.is_finished() {
					certificates.push(read_octet(&mut inner)?.to_vec());
				}

				Some(IntermediateCertificates::Bundle(certificates))
			}
			other => return Err(unexpected_tag(other)),
		}
	};

	Ok(ManageCertificateOp { method, certificate_or_hash, intermediate_certificates })
}

// --- Permissions ---------------------------------------------------------

fn encode_permissions(out: &mut Vec<u8>, value: &Permissions) -> Result<(), Asn1Error> {
	let mut content = Vec::new();
	encode_bigint(&mut content, &value.base)?;
	encode_bigint(&mut content, &value.external)?;
	out.extend_from_slice(&wrap_sequence(&content)?);
	Ok(())
}

fn read_permissions(reader: &mut SliceReader<'_>) -> Result<Permissions, Asn1Error> {
	let content = read_sequence(reader)?;
	let mut inner = SliceReader::new(content)?;
	let base = read_bigint(&mut inner)?;
	let external = read_bigint(&mut inner)?;
	if !inner.is_finished() {
		return Err(invalid_block());
	}

	Ok(Permissions { base, external })
}
