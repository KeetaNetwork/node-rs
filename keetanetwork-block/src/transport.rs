//! Conversions between block domain types and the backend-neutral
//! `keetanetwork_asn1::block` transport types.

use std::sync::Arc;

use keetanetwork_account::KeyPairType;
use keetanetwork_asn1::block as asn1;
use keetanetwork_crypto::hash::BlockHash;
use num_bigint::BigInt;

use crate::account_util::{accounts_equal, parse_account_with_type};
use crate::amount::Amount;
use crate::block::{BlockData, BlockPurpose, BlockVersion, Signature, MAX_PARSE_SIGNER_DEPTH};
use crate::error::BlockError;
use crate::operation::{
	AdjustMethod, CertificateDer, CertificateOrHash, CreateIdentifier, IdentifierCreateArguments,
	IntermediateCertificates, ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal,
	MultisigCreateArguments, Operation, Receive, Send, SetInfo, SetRep, TokenAdminModifyBalance, TokenAdminSupply,
};
use crate::permissions::Permissions;
use crate::signer::{AccountRef, Signer};

const BLOCK_HASH_LEN: usize = 32;

// --- Top-level encode/decode --------------------------------------------

pub(crate) fn encode_block(data: &BlockData, signatures: Option<&[Signature]>) -> Result<Vec<u8>, BlockError> {
	match data.version {
		BlockVersion::V1 => Ok(asn1::encode_v1(&build_block_v1(data, signatures)?)?),
		BlockVersion::V2 => Ok(asn1::encode_v2(&build_block_v2(data, signatures)?)?),
	}
}

pub(crate) fn decode_block(bytes: &[u8]) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	match asn1::decode(bytes)? {
		asn1::Block::V1(v1) => block_v1_to_parts(v1),
		asn1::Block::V2(v2) => block_v2_to_parts(v2),
	}
}

// --- Block V1 -----------------------------------------------------------

fn build_block_v1(data: &BlockData, signatures: Option<&[Signature]>) -> Result<asn1::BlockV1, BlockError> {
	let Signer::Single(signer_account) = &data.signer else {
		return Err(BlockError::V1SingleSignerOnly);
	};

	let subnet = match &data.subnet {
		Some(value) => asn1::IntegerOrNull::Value(value.clone()),
		None => asn1::IntegerOrNull::Null,
	};

	let account = if accounts_equal(&data.account, signer_account) {
		asn1::OctetStringOrNull::Null
	} else {
		asn1::OctetStringOrNull::Value(account_bytes(&data.account))
	};

	let signature = match signatures {
		None => None,
		Some([only]) => Some(only.as_ref().to_vec()),
		Some(_) => return Err(BlockError::V1SingleSignerOnly),
	};

	Ok(asn1::BlockV1 {
		version: BigInt::ZERO,
		network: data.network.clone(),
		subnet,
		idempotent: data.idempotent.clone(),
		date: data.date.into(),
		signer: account_bytes(signer_account),
		account,
		previous: data.previous.as_bytes().to_vec(),
		operations: data
			.operations
			.iter()
			.map(operation_to_transport)
			.collect::<Result<Vec<_>, _>>()?,
		signature,
	})
}

fn block_v1_to_parts(value: asn1::BlockV1) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	if value.version != BigInt::ZERO {
		return Err(BlockError::InvalidVersion);
	}

	let signer_account = parse_account(&value.signer)?;
	let signer = Signer::Single(signer_account.clone());

	let account = match value.account {
		asn1::OctetStringOrNull::Null => signer_account.clone(),
		asn1::OctetStringOrNull::Value(bytes) => {
			let parsed = parse_account(&bytes)?;
			if accounts_equal(&parsed, &signer_account) {
				return Err(BlockError::RedundantAccountField);
			}
			parsed
		}
	};

	let subnet = match value.subnet {
		asn1::IntegerOrNull::Null => None,
		asn1::IntegerOrNull::Value(integer) => Some(integer),
	};

	let signatures = value
		.signature
		.map(|bytes| Signature::try_from(bytes.as_slice()).map(|sig| vec![sig]))
		.transpose()?;

	let data = BlockData {
		version: BlockVersion::V1,
		purpose: BlockPurpose::Generic,
		network: value.network,
		subnet,
		idempotent: value.idempotent,
		date: value.date.into(),
		account,
		signer,
		previous: blockhash_from_bytes(&value.previous)?,
		operations: value
			.operations
			.into_iter()
			.map(operation_from_transport)
			.collect::<Result<Vec<_>, _>>()?,
	};

	Ok((data, signatures))
}

// --- Block V2 -----------------------------------------------------------

fn build_block_v2(data: &BlockData, signatures: Option<&[Signature]>) -> Result<asn1::BlockV2, BlockError> {
	let signer_transport = match &data.signer {
		Signer::Single(account) if accounts_equal(account, &data.account) => asn1::Signer::Empty,
		Signer::Single(account) => asn1::Signer::Single(account_bytes(account)),
		Signer::Multisig { address, signers } => asn1::Signer::Multisig(build_multisig(address, signers)?),
	};

	let signatures_transport = match signatures {
		None => None,
		Some([]) => return Err(BlockError::SignatureRequired),
		Some([only]) => Some(asn1::Signatures::Single(only.as_ref().to_vec())),
		Some(many) => Some(asn1::Signatures::Multiple(many.iter().map(|sig| sig.as_ref().to_vec()).collect())),
	};

	let body = asn1::BlockV2Body {
		network: data.network.clone(),
		subnet: data.subnet.clone(),
		idempotent: data.idempotent.clone(),
		date: data.date.into(),
		purpose: data.purpose.to_bigint(),
		account: account_bytes(&data.account),
		signer: signer_transport,
		previous: data.previous.as_bytes().to_vec(),
		operations: data
			.operations
			.iter()
			.map(operation_to_transport)
			.collect::<Result<Vec<_>, _>>()?,
		signatures: signatures_transport,
	};

	Ok(asn1::BlockV2(body))
}

fn block_v2_to_parts(value: asn1::BlockV2) -> Result<(BlockData, Option<Vec<Signature>>), BlockError> {
	let body = value.0;

	let account = parse_account(&body.account)?;

	let signer = match body.signer {
		asn1::Signer::Empty => Signer::Single(account.clone()),
		asn1::Signer::Single(bytes) => {
			let signer = parse_account(&bytes)?;
			if accounts_equal(&signer, &account) {
				return Err(BlockError::RedundantAccountField);
			}
			Signer::Single(signer)
		}
		asn1::Signer::Multisig(multi) => parse_multisig(multi, 1)?,
	};

	let signatures = match body.signatures {
		None => None,
		Some(asn1::Signatures::Single(bytes)) => Some(vec![Signature::try_from(bytes.as_slice())?]),
		Some(asn1::Signatures::Multiple(many)) => {
			if many.len() <= 1 {
				return Err(BlockError::InvalidSignatureSequence);
			}

			Some(
				many.iter()
					.map(|bytes| Signature::try_from(bytes.as_slice()))
					.collect::<Result<Vec<_>, _>>()?,
			)
		}
	};

	let data = BlockData {
		version: BlockVersion::V2,
		purpose: BlockPurpose::try_from(&body.purpose)?,
		network: body.network,
		subnet: body.subnet,
		idempotent: body.idempotent,
		date: body.date.into(),
		account,
		signer,
		previous: blockhash_from_bytes(&body.previous)?,
		operations: body
			.operations
			.into_iter()
			.map(operation_from_transport)
			.collect::<Result<Vec<_>, _>>()?,
	};

	Ok((data, signatures))
}

// --- Multisig signer ----------------------------------------------------

fn build_multisig(address: &AccountRef, signers: &[Signer]) -> Result<asn1::MultisigSigner, BlockError> {
	let nested = signers
		.iter()
		.map(build_signer)
		.collect::<Result<Vec<_>, _>>()?;
	Ok(asn1::MultisigSigner { address: account_bytes(address), signers: nested })
}

fn build_signer(value: &Signer) -> Result<asn1::Signer, BlockError> {
	match value {
		Signer::Single(account) => Ok(asn1::Signer::Single(account_bytes(account))),
		Signer::Multisig { address, signers } => Ok(asn1::Signer::Multisig(build_multisig(address, signers)?)),
	}
}

fn parse_multisig(value: asn1::MultisigSigner, depth: usize) -> Result<Signer, BlockError> {
	let address = parse_account(&value.address)?;
	if address.to_keypair_type() != KeyPairType::MULTISIG {
		return Err(BlockError::MalformedSigner);
	}

	let signers = value
		.signers
		.into_iter()
		.map(|child| parse_signer(child, depth + 1))
		.collect::<Result<Vec<_>, _>>()?;

	Ok(Signer::Multisig { address, signers })
}

fn parse_signer(value: asn1::Signer, depth: usize) -> Result<Signer, BlockError> {
	match value {
		asn1::Signer::Single(bytes) => Ok(Signer::Single(parse_account(&bytes)?)),
		asn1::Signer::Multisig(multi) => {
			if depth > MAX_PARSE_SIGNER_DEPTH {
				return Err(BlockError::MultisigSignerDepthExceeded {
					depth: depth as u64,
					max: MAX_PARSE_SIGNER_DEPTH as u64,
				});
			}

			parse_multisig(multi, depth)
		}
		asn1::Signer::Empty => Err(BlockError::MalformedSigner),
	}
}

// --- Operations ---------------------------------------------------------

fn operation_to_transport(operation: &Operation) -> Result<asn1::Operation, BlockError> {
	let transport = match operation {
		Operation::Send(op) => asn1::Operation::Send(asn1::SendOp {
			to: account_bytes(&op.to),
			amount: op.amount.as_bigint().clone(),
			token: account_bytes(&op.token),
			external: op.external.clone(),
		}),
		Operation::SetRep(op) => asn1::Operation::SetRep(asn1::SetRepOp { to: account_bytes(&op.to) }),
		Operation::SetInfo(op) => asn1::Operation::SetInfo(asn1::SetInfoOp {
			name: op.name.clone(),
			description: op.description.clone(),
			metadata: op.metadata.clone(),
			default_permission: op.default_permission.as_ref().map(permissions_to_transport),
		}),
		Operation::ModifyPermissions(op) => asn1::Operation::ModifyPermissions(modify_permissions_to_transport(op)),
		Operation::CreateIdentifier(op) => asn1::Operation::CreateIdentifier(create_identifier_to_transport(op)?),
		Operation::TokenAdminSupply(op) => asn1::Operation::TokenAdminSupply(asn1::TokenAdminSupplyOp {
			amount: op.amount.as_bigint().clone(),
			method: op.method.to_bigint(),
		}),
		Operation::TokenAdminModifyBalance(op) => {
			asn1::Operation::TokenAdminModifyBalance(asn1::TokenAdminModifyBalanceOp {
				token: account_bytes(&op.token),
				amount: op.amount.as_bigint().clone(),
				method: op.method.to_bigint(),
			})
		}
		Operation::Receive(op) => asn1::Operation::Receive(asn1::ReceiveOp {
			amount: op.amount.as_bigint().clone(),
			token: account_bytes(&op.token),
			from: account_bytes(&op.from),
			exact: op.exact,
			forward: op.forward.as_ref().map(account_bytes),
		}),
		Operation::ManageCertificate(op) => asn1::Operation::ManageCertificate(manage_certificate_to_transport(op)),
	};
	Ok(transport)
}

fn operation_from_transport(value: asn1::Operation) -> Result<Operation, BlockError> {
	match value {
		asn1::Operation::Send(op) => Ok(Operation::Send(Send {
			to: parse_account(&op.to)?,
			amount: Amount::from(op.amount),
			token: parse_account(&op.token)?,
			external: op.external,
		})),
		asn1::Operation::SetRep(op) => Ok(Operation::SetRep(SetRep { to: parse_account(&op.to)? })),
		asn1::Operation::SetInfo(op) => Ok(Operation::SetInfo(SetInfo {
			name: op.name,
			description: op.description,
			metadata: op.metadata,
			default_permission: op
				.default_permission
				.map(permissions_from_transport)
				.transpose()?,
		})),
		asn1::Operation::ModifyPermissions(op) => {
			Ok(Operation::ModifyPermissions(modify_permissions_from_transport(op)?))
		}
		asn1::Operation::CreateIdentifier(op) => Ok(Operation::CreateIdentifier(create_identifier_from_transport(op)?)),
		asn1::Operation::TokenAdminSupply(op) => Ok(Operation::TokenAdminSupply(TokenAdminSupply {
			amount: Amount::from(op.amount),
			method: AdjustMethod::try_from(&op.method)?,
		})),
		asn1::Operation::TokenAdminModifyBalance(op) => {
			Ok(Operation::TokenAdminModifyBalance(TokenAdminModifyBalance {
				token: parse_account(&op.token)?,
				amount: Amount::from(op.amount),
				method: AdjustMethod::try_from(&op.method)?,
			}))
		}
		asn1::Operation::Receive(op) => Ok(Operation::Receive(Receive {
			amount: Amount::from(op.amount),
			token: parse_account(&op.token)?,
			from: parse_account(&op.from)?,
			exact: op.exact,
			forward: op.forward.map(|bytes| parse_account(&bytes)).transpose()?,
		})),
		asn1::Operation::ManageCertificate(op) => {
			Ok(Operation::ManageCertificate(manage_certificate_from_transport(op)?))
		}
	}
}

// --- ModifyPermissions --------------------------------------------------

fn modify_permissions_to_transport(value: &ModifyPermissions) -> asn1::ModifyPermissionsOp {
	let principal = match &value.principal {
		ModifyPermissionsPrincipal::Account(account) => {
			asn1::ModifyPermissionsPrincipal::Account(account_bytes(account))
		}
		ModifyPermissionsPrincipal::Certificate { hash, account } => {
			asn1::ModifyPermissionsPrincipal::Certificate(asn1::CertificatePrincipal {
				hash: hash.to_vec(),
				account: account_bytes(account),
			})
		}
	};

	let permissions = match &value.permissions {
		Some(permissions) => asn1::PermissionsOrNull::Permissions(permissions_to_transport(permissions)),
		None => asn1::PermissionsOrNull::Null,
	};

	asn1::ModifyPermissionsOp {
		principal,
		method: value.method.to_bigint(),
		permissions,
		target: value.target.as_ref().map(account_bytes),
	}
}

fn modify_permissions_from_transport(value: asn1::ModifyPermissionsOp) -> Result<ModifyPermissions, BlockError> {
	let principal = match value.principal {
		asn1::ModifyPermissionsPrincipal::Account(bytes) => ModifyPermissionsPrincipal::Account(parse_account(&bytes)?),
		asn1::ModifyPermissionsPrincipal::Certificate(certificate) => {
			let hash: [u8; BLOCK_HASH_LEN] = certificate
				.hash
				.as_slice()
				.try_into()
				.map_err(|_| BlockError::InvalidPrincipal)?;
			ModifyPermissionsPrincipal::Certificate { hash, account: parse_account(&certificate.account)? }
		}
	};

	let permissions = match value.permissions {
		asn1::PermissionsOrNull::Permissions(perms) => Some(permissions_from_transport(perms)?),
		asn1::PermissionsOrNull::Null => None,
	};

	Ok(ModifyPermissions {
		principal,
		method: AdjustMethod::try_from(&value.method)?,
		permissions,
		target: value
			.target
			.map(|bytes| parse_account(&bytes))
			.transpose()?,
	})
}

// --- CreateIdentifier ---------------------------------------------------

fn create_identifier_to_transport(value: &CreateIdentifier) -> Result<asn1::CreateIdentifierOp, BlockError> {
	let multisig = value
		.create_arguments
		.as_ref()
		.map(|IdentifierCreateArguments::Multisig(arguments)| asn1::MultisigArguments {
			signers: arguments.signers.iter().map(account_bytes).collect(),
			quorum: arguments.quorum.clone(),
		});

	Ok(asn1::CreateIdentifierOp { identifier: account_bytes(&value.identifier), multisig })
}

fn create_identifier_from_transport(value: asn1::CreateIdentifierOp) -> Result<CreateIdentifier, BlockError> {
	let identifier = parse_account(&value.identifier)?;

	let create_arguments = match value.multisig {
		None => None,
		Some(arguments) => {
			let signers = arguments
				.signers
				.iter()
				.map(|bytes| parse_account(bytes))
				.collect::<Result<Vec<_>, _>>()?;
			Some(IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum: arguments.quorum }))
		}
	};

	Ok(CreateIdentifier { identifier, create_arguments })
}

// --- ManageCertificate --------------------------------------------------

fn manage_certificate_to_transport(value: &ManageCertificate) -> asn1::ManageCertificateOp {
	let certificate_or_hash = match &value.certificate_or_hash {
		CertificateOrHash::Certificate(certificate) => {
			// Removals always reference the certificate by hash.
			if value.method == AdjustMethod::Subtract {
				certificate.hash().to_vec()
			} else {
				certificate.as_bytes().to_vec()
			}
		}
		CertificateOrHash::Hash(hash) => hash.to_vec(),
	};

	let intermediate_certificates = value
		.intermediate_certificates
		.as_ref()
		.map(|inter| match inter {
			IntermediateCertificates::None => asn1::IntermediateCertificates::Null,
			IntermediateCertificates::Bundle(bundle) => asn1::IntermediateCertificates::Bundle(
				bundle
					.iter()
					.map(|certificate| certificate.as_bytes().to_vec())
					.collect(),
			),
		});

	asn1::ManageCertificateOp { method: value.method.to_bigint(), certificate_or_hash, intermediate_certificates }
}

fn manage_certificate_from_transport(value: asn1::ManageCertificateOp) -> Result<ManageCertificate, BlockError> {
	let bytes = value.certificate_or_hash.as_slice();
	let certificate_or_hash = match <[u8; BLOCK_HASH_LEN]>::try_from(bytes) {
		Ok(hash) => CertificateOrHash::Hash(hash),
		Err(_) => CertificateOrHash::Certificate(CertificateDer::from(bytes.to_vec())),
	};

	let intermediate_certificates = value.intermediate_certificates.map(|inter| match inter {
		asn1::IntermediateCertificates::Null => IntermediateCertificates::None,
		asn1::IntermediateCertificates::Bundle(bundle) => {
			IntermediateCertificates::Bundle(bundle.into_iter().map(CertificateDer::from).collect())
		}
	});

	Ok(ManageCertificate {
		method: AdjustMethod::try_from(&value.method)?,
		certificate_or_hash,
		intermediate_certificates,
	})
}

// --- Permissions --------------------------------------------------------

fn permissions_to_transport(value: &Permissions) -> asn1::Permissions {
	asn1::Permissions { base: value.base().as_bigint().clone(), external: value.external().as_bigint().clone() }
}

fn permissions_from_transport(value: asn1::Permissions) -> Result<Permissions, BlockError> {
	Permissions::from_bigints(value.base, value.external)
}

// --- Primitive helpers --------------------------------------------------

fn account_bytes(account: &AccountRef) -> Vec<u8> {
	account.to_public_key_with_type()
}

fn parse_account(bytes: &[u8]) -> Result<AccountRef, BlockError> {
	Ok(Arc::new(parse_account_with_type(bytes)?))
}

fn blockhash_from_bytes(bytes: &[u8]) -> Result<BlockHash, BlockError> {
	Ok(BlockHash::try_from(bytes)?)
}
