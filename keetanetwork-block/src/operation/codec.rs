//! DER codec for block operations.
//!
//! Each operation is encoded as `[type] EXPLICIT SEQUENCE { fields... }`,
//! where `type` is the operation discriminant (0-8).

use crate::error::BlockError;
use crate::operation::{
	AdjustMethod, CertificateDer, CertificateOrHash, CreateIdentifier, IdentifierCreateArguments,
	IntermediateCertificates, ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal,
	MultisigCreateArguments, Operation, OperationType, Receive, Send, SetInfo, SetRep, TokenAdminModifyBalance,
	TokenAdminSupply,
};
use crate::permissions::Permissions;
use crate::wire::{
	encode_account, encode_bigint, encode_bool, encode_null, encode_octet, encode_utf8, read_account, read_bigint,
	read_bool, read_null, read_octet, read_sequence, read_utf8, unexpected_tag, wrap_context, wrap_sequence,
};
use der::asn1::AnyRef;
use der::{Decode, Reader, SliceReader, Tag, TagNumber, Tagged};

/// Context tag of a certificate principal in MODIFY_PERMISSIONS.
const CERTIFICATE_PRINCIPAL_TAG: TagNumber = TagNumber::N1;
/// Context tag of multisig create arguments (the MULTISIG key type value).
const MULTISIG_ARGUMENTS_TAG: TagNumber = TagNumber::N7;

fn operation_tag(operation_type: OperationType) -> TagNumber {
	match operation_type {
		OperationType::Send => TagNumber::N0,
		OperationType::SetRep => TagNumber::N1,
		OperationType::SetInfo => TagNumber::N2,
		OperationType::ModifyPermissions => TagNumber::N3,
		OperationType::CreateIdentifier => TagNumber::N4,
		OperationType::TokenAdminSupply => TagNumber::N5,
		OperationType::TokenAdminModifyBalance => TagNumber::N6,
		OperationType::Receive => TagNumber::N7,
		OperationType::ManageCertificate => TagNumber::N8,
	}
}

fn encode_permissions(out: &mut Vec<u8>, permissions: &Permissions) -> Result<(), BlockError> {
	let mut content = Vec::new();
	encode_bigint(&mut content, permissions.base().as_bigint())?;
	encode_bigint(&mut content, permissions.external().as_bigint())?;
	out.extend_from_slice(&wrap_sequence(&content)?);
	Ok(())
}

fn read_permissions(reader: &mut SliceReader<'_>) -> Result<Permissions, BlockError> {
	let content = read_sequence(reader)?;
	let mut inner = SliceReader::new(content)?;
	let base = read_bigint(&mut inner)?;
	let external = read_bigint(&mut inner)?;
	if !inner.is_finished() {
		return Err(BlockError::InvalidOperationType);
	}

	Permissions::from_bigints(base, external)
}

fn read_adjust_method(reader: &mut SliceReader<'_>) -> Result<AdjustMethod, BlockError> {
	AdjustMethod::try_from(&read_bigint(reader)?)
}

impl Send {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_account(out, &self.to)?;
		encode_bigint(out, self.amount.as_bigint())?;
		encode_account(out, &self.token)?;
		if let Some(external) = &self.external {
			encode_utf8(out, external)?;
		}
		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let to = read_account(reader)?;
		let amount = read_bigint(reader)?.into();
		let token = read_account(reader)?;
		let external = if reader.is_finished() {
			None
		} else {
			Some(read_utf8(reader)?)
		};

		Ok(Self { to, amount, token, external })
	}
}

impl SetRep {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_account(out, &self.to)
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		Ok(Self { to: read_account(reader)? })
	}
}

impl SetInfo {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_utf8(out, &self.name)?;
		encode_utf8(out, &self.description)?;
		encode_utf8(out, &self.metadata)?;
		if let Some(default_permission) = &self.default_permission {
			encode_permissions(out, default_permission)?;
		}
		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let name = read_utf8(reader)?;
		let description = read_utf8(reader)?;
		let metadata = read_utf8(reader)?;
		let default_permission = if reader.is_finished() {
			None
		} else {
			Some(read_permissions(reader)?)
		};

		Ok(Self { name, description, metadata, default_permission })
	}
}

impl ModifyPermissions {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		match &self.principal {
			ModifyPermissionsPrincipal::Account(account) => encode_account(out, account)?,
			ModifyPermissionsPrincipal::Certificate { hash, account } => {
				let mut content = Vec::new();
				encode_octet(&mut content, hash)?;
				encode_account(&mut content, account)?;
				let sequence = wrap_sequence(&content)?;
				out.extend_from_slice(&wrap_context(CERTIFICATE_PRINCIPAL_TAG, &sequence)?);
			}
		}

		encode_bigint(out, &self.method.to_bigint())?;

		match &self.permissions {
			Some(permissions) => encode_permissions(out, permissions)?,
			None => encode_null(out)?,
		}

		if let Some(target) = &self.target {
			encode_account(out, target)?;
		}

		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let principal = match reader.peek_tag()? {
			Tag::OctetString => ModifyPermissionsPrincipal::Account(read_account(reader)?),
			Tag::ContextSpecific { constructed: true, number } if number == CERTIFICATE_PRINCIPAL_TAG => {
				let any = AnyRef::decode(reader)?;
				let mut outer = SliceReader::new(any.value())?;
				let content = read_sequence(&mut outer)?;
				if !outer.is_finished() {
					return Err(BlockError::InvalidPrincipal);
				}

				let mut inner = SliceReader::new(content)?;
				let hash_bytes = read_octet(&mut inner)?;
				let hash: [u8; 32] = hash_bytes
					.try_into()
					.map_err(|_| BlockError::InvalidPrincipal)?;
				let account = read_account(&mut inner)?;
				if !inner.is_finished() {
					return Err(BlockError::InvalidPrincipal);
				}

				ModifyPermissionsPrincipal::Certificate { hash, account }
			}
			_ => return Err(BlockError::InvalidPrincipal),
		};

		let method = read_adjust_method(reader)?;

		let permissions = match reader.peek_tag()? {
			Tag::Null => {
				read_null(reader)?;
				None
			}
			Tag::Sequence => Some(read_permissions(reader)?),
			other => return Err(unexpected_tag(other)),
		};

		let target = if reader.is_finished() {
			None
		} else {
			Some(read_account(reader)?)
		};

		Ok(Self { principal, method, permissions, target })
	}
}

impl CreateIdentifier {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_account(out, &self.identifier)?;

		if let Some(IdentifierCreateArguments::Multisig(arguments)) = &self.create_arguments {
			let mut signers = Vec::new();
			for signer in &arguments.signers {
				encode_account(&mut signers, signer)?;
			}

			let mut content = wrap_sequence(&signers)?;
			encode_bigint(&mut content, &arguments.quorum)?;
			let sequence = wrap_sequence(&content)?;
			out.extend_from_slice(&wrap_context(MULTISIG_ARGUMENTS_TAG, &sequence)?);
		}

		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let identifier = read_account(reader)?;

		let create_arguments = if reader.is_finished() {
			None
		} else {
			match reader.peek_tag()? {
				Tag::ContextSpecific { constructed: true, number } if number == MULTISIG_ARGUMENTS_TAG => {
					let any = AnyRef::decode(reader)?;
					let mut outer = SliceReader::new(any.value())?;
					let content = read_sequence(&mut outer)?;
					if !outer.is_finished() {
						return Err(BlockError::InvalidCreateIdentifierArguments);
					}

					let mut inner = SliceReader::new(content)?;
					let signers_content = read_sequence(&mut inner)?;
					let mut signers_reader = SliceReader::new(signers_content)?;
					let mut signers = Vec::new();
					while !signers_reader.is_finished() {
						signers.push(read_account(&mut signers_reader)?);
					}

					let quorum = read_bigint(&mut inner)?;
					if !inner.is_finished() {
						return Err(BlockError::InvalidCreateIdentifierArguments);
					}

					Some(IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum }))
				}
				_ => return Err(BlockError::InvalidCreateIdentifierArguments),
			}
		};

		Ok(Self { identifier, create_arguments })
	}
}

impl TokenAdminSupply {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_bigint(out, self.amount.as_bigint())?;
		encode_bigint(out, &self.method.to_bigint())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let amount = read_bigint(reader)?.into();
		let method = read_adjust_method(reader)?;
		Ok(Self { amount, method })
	}
}

impl TokenAdminModifyBalance {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_account(out, &self.token)?;
		encode_bigint(out, self.amount.as_bigint())?;
		encode_bigint(out, &self.method.to_bigint())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let token = read_account(reader)?;
		let amount = read_bigint(reader)?.into();
		let method = read_adjust_method(reader)?;
		Ok(Self { token, amount, method })
	}
}

impl Receive {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_bigint(out, self.amount.as_bigint())?;
		encode_account(out, &self.token)?;
		encode_account(out, &self.from)?;
		encode_bool(out, self.exact)?;
		if let Some(forward) = &self.forward {
			encode_account(out, forward)?;
		}
		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let amount = read_bigint(reader)?.into();
		let token = read_account(reader)?;
		let from = read_account(reader)?;
		let exact = read_bool(reader)?;
		let forward = if reader.is_finished() {
			None
		} else {
			Some(read_account(reader)?)
		};

		Ok(Self { amount, token, from, exact, forward })
	}
}

impl ManageCertificate {
	fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), BlockError> {
		encode_bigint(out, &self.method.to_bigint())?;

		match &self.certificate_or_hash {
			CertificateOrHash::Certificate(certificate) => {
				// Removals always reference the certificate by hash.
				if self.method == AdjustMethod::Subtract {
					encode_octet(out, &certificate.hash())?;
				} else {
					encode_octet(out, certificate.as_bytes())?;
				}
			}
			CertificateOrHash::Hash(hash) => encode_octet(out, hash)?,
		}

		match &self.intermediate_certificates {
			None => {}
			Some(IntermediateCertificates::None) => encode_null(out)?,
			Some(IntermediateCertificates::Bundle(certificates)) => {
				let mut content = Vec::new();
				for certificate in certificates {
					encode_octet(&mut content, certificate.as_bytes())?;
				}
				out.extend_from_slice(&wrap_sequence(&content)?);
			}
		}

		Ok(())
	}

	fn decode_fields(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let method = read_adjust_method(reader)?;

		let value = read_octet(reader)?;
		let certificate_or_hash = match <[u8; 32]>::try_from(value) {
			Ok(hash) => CertificateOrHash::Hash(hash),
			Err(_) => CertificateOrHash::Certificate(CertificateDer::from(value.to_vec())),
		};

		let intermediate_certificates = if reader.is_finished() {
			None
		} else {
			match reader.peek_tag()? {
				Tag::Null => {
					read_null(reader)?;
					Some(IntermediateCertificates::None)
				}
				Tag::Sequence => {
					let content = read_sequence(reader)?;
					let mut inner = SliceReader::new(content)?;
					let mut certificates = Vec::new();
					while !inner.is_finished() {
						certificates.push(CertificateDer::from(read_octet(&mut inner)?.to_vec()));
					}

					Some(IntermediateCertificates::Bundle(certificates))
				}
				other => return Err(unexpected_tag(other)),
			}
		};

		Ok(Self { method, certificate_or_hash, intermediate_certificates })
	}
}

impl Operation {
	/// Encode as `[type] EXPLICIT SEQUENCE { fields }`.
	pub(crate) fn to_wire(&self) -> Result<Vec<u8>, BlockError> {
		let mut fields = Vec::new();
		match self {
			Operation::Send(op) => op.encode_fields(&mut fields)?,
			Operation::SetRep(op) => op.encode_fields(&mut fields)?,
			Operation::SetInfo(op) => op.encode_fields(&mut fields)?,
			Operation::ModifyPermissions(op) => op.encode_fields(&mut fields)?,
			Operation::CreateIdentifier(op) => op.encode_fields(&mut fields)?,
			Operation::TokenAdminSupply(op) => op.encode_fields(&mut fields)?,
			Operation::TokenAdminModifyBalance(op) => op.encode_fields(&mut fields)?,
			Operation::Receive(op) => op.encode_fields(&mut fields)?,
			Operation::ManageCertificate(op) => op.encode_fields(&mut fields)?,
		}

		wrap_context(operation_tag(self.operation_type()), &wrap_sequence(&fields)?)
	}

	/// Decode one operation from a sequence-of-operations reader.
	pub(crate) fn from_wire(reader: &mut SliceReader<'_>) -> Result<Self, BlockError> {
		let any = AnyRef::decode(reader)?;
		let Tag::ContextSpecific { constructed: true, number } = any.tag() else {
			return Err(BlockError::InvalidOperationType);
		};

		let mut outer = SliceReader::new(any.value())?;
		let content = read_sequence(&mut outer)?;
		if !outer.is_finished() {
			return Err(BlockError::InvalidOperationType);
		}

		let mut fields = SliceReader::new(content)?;

		let operation = match number.value() {
			0 => Operation::Send(Send::decode_fields(&mut fields)?),
			1 => Operation::SetRep(SetRep::decode_fields(&mut fields)?),
			2 => Operation::SetInfo(SetInfo::decode_fields(&mut fields)?),
			3 => Operation::ModifyPermissions(ModifyPermissions::decode_fields(&mut fields)?),
			4 => Operation::CreateIdentifier(CreateIdentifier::decode_fields(&mut fields)?),
			5 => Operation::TokenAdminSupply(TokenAdminSupply::decode_fields(&mut fields)?),
			6 => Operation::TokenAdminModifyBalance(TokenAdminModifyBalance::decode_fields(&mut fields)?),
			7 => Operation::Receive(Receive::decode_fields(&mut fields)?),
			8 => Operation::ManageCertificate(ManageCertificate::decode_fields(&mut fields)?),
			_ => return Err(BlockError::InvalidOperationType),
		};

		if !fields.is_finished() {
			return Err(BlockError::InvalidOperationType);
		}

		Ok(operation)
	}
}
