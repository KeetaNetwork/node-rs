//! `rasn`-backed encode/decode that converts the public neutral types in
//! [`super::super::types`] into the rasn-compiler-generated transport types in
//! `crate::generated` and back.

use alloc::format;
use alloc::vec::Vec;

use crate::block::types::{
	Block, BlockV1, BlockV2, BlockV2Body, CertificatePrincipal, CreateIdentifierOp, IntegerOrNull,
	IntermediateCertificates, ManageCertificateOp, ModifyPermissionsOp, ModifyPermissionsPrincipal, MultisigArguments,
	MultisigSigner, OctetStringOrNull, Operation, Permissions, PermissionsOrNull, ReceiveOp, SendOp, SetInfoOp,
	SetRepOp, Signatures, Signer, TokenAdminModifyBalanceOp, TokenAdminSupplyOp,
};
use crate::generated as gen;
use crate::rasn::{Integer, OctetString};
use crate::Asn1Error;
use num_bigint::{BigInt, ToBigInt};

// --- public entry points --------------------------------------------------

pub(super) fn encode_v1(value: &BlockV1) -> Result<Vec<u8>, Asn1Error> {
	let transport = block_v1_to_transport(value);
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn encode_v2(value: &BlockV2) -> Result<Vec<u8>, Asn1Error> {
	let transport = block_v2_to_transport(value);
	::rasn::der::encode(&transport).map_err(Asn1Error::from)
}

pub(super) fn decode_v1(bytes: &[u8]) -> Result<BlockV1, Asn1Error> {
	let transport: gen::BlockV1 = ::rasn::der::decode(bytes)
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	Ok(block_v1_from_transport(transport))
}

pub(super) fn decode_v2(bytes: &[u8]) -> Result<BlockV2, Asn1Error> {
	let transport: gen::BlockV2 = ::rasn::der::decode(bytes)
		.map_err(|error| Asn1Error::RasnError { reason: format!("decode error: {error}") })?;
	Ok(block_v2_from_transport(transport))
}

#[allow(dead_code)]
pub(super) fn encode_block(value: &Block) -> Result<Vec<u8>, Asn1Error> {
	match value {
		Block::V1(v1) => encode_v1(v1),
		Block::V2(v2) => encode_v2(v2),
	}
}

// --- BlockV1 conversion ---------------------------------------------------

fn block_v1_to_transport(value: &BlockV1) -> gen::BlockV1 {
	gen::BlockV1 {
		version: bigint_to_integer(&value.version),
		network: bigint_to_integer(&value.network),
		subnet: integer_or_null_to_transport(&value.subnet),
		idempotent: value.idempotent.as_ref().map(bytes_to_octet),
		date: value.date,
		signer: bytes_to_octet(&value.signer),
		account: octet_or_null_to_transport(&value.account),
		previous: bytes_to_octet(&value.previous),
		operations: value
			.operations
			.iter()
			.map(operation_to_transport)
			.collect(),
		signature: value.signature.as_ref().map(bytes_to_octet),
	}
}

fn block_v1_from_transport(value: gen::BlockV1) -> BlockV1 {
	BlockV1 {
		version: integer_to_bigint(&value.version),
		network: integer_to_bigint(&value.network),
		subnet: integer_or_null_from_transport(value.subnet),
		idempotent: value.idempotent.map(octet_to_bytes),
		date: value.date,
		signer: octet_to_bytes(value.signer),
		account: octet_or_null_from_transport(value.account),
		previous: octet_to_bytes(value.previous),
		operations: value
			.operations
			.into_iter()
			.map(operation_from_transport)
			.collect(),
		signature: value.signature.map(octet_to_bytes),
	}
}

// --- BlockV2 conversion ---------------------------------------------------

fn block_v2_to_transport(value: &BlockV2) -> gen::BlockV2 {
	let body = gen::BlockV2Body {
		network: bigint_to_integer(&value.0.network),
		subnet: value.0.subnet.as_ref().map(bigint_to_integer),
		idempotent: value.0.idempotent.as_ref().map(bytes_to_octet),
		date: value.0.date,
		purpose: bigint_to_integer(&value.0.purpose),
		account: bytes_to_octet(&value.0.account),
		signer: signer_to_transport(&value.0.signer),
		previous: bytes_to_octet(&value.0.previous),
		operations: value
			.0
			.operations
			.iter()
			.map(operation_to_transport)
			.collect(),
		signatures: value.0.signatures.as_ref().map(signatures_to_transport),
	};
	gen::BlockV2(body)
}

fn block_v2_from_transport(value: gen::BlockV2) -> BlockV2 {
	let body = value.0;
	BlockV2(BlockV2Body {
		network: integer_to_bigint(&body.network),
		subnet: body.subnet.as_ref().map(integer_to_bigint),
		idempotent: body.idempotent.map(octet_to_bytes),
		date: body.date,
		purpose: integer_to_bigint(&body.purpose),
		account: octet_to_bytes(body.account),
		signer: signer_from_transport(body.signer),
		previous: octet_to_bytes(body.previous),
		operations: body
			.operations
			.into_iter()
			.map(operation_from_transport)
			.collect(),
		signatures: body.signatures.map(signatures_from_transport),
	})
}

// --- Signer ---------------------------------------------------------------

fn signer_to_transport(value: &Signer) -> gen::Signer {
	match value {
		Signer::Empty => gen::Signer::empty(()),
		Signer::Single(bytes) => gen::Signer::single(bytes_to_octet(bytes)),
		Signer::Multisig(multi) => gen::Signer::multisig(multisig_to_transport(multi)),
	}
}

fn signer_from_transport(value: gen::Signer) -> Signer {
	match value {
		gen::Signer::empty(()) => Signer::Empty,
		gen::Signer::single(bytes) => Signer::Single(octet_to_bytes(bytes)),
		gen::Signer::multisig(multi) => Signer::Multisig(multisig_from_transport(multi)),
	}
}

fn multisig_to_transport(value: &MultisigSigner) -> gen::MultisigSigner {
	gen::MultisigSigner {
		address: bytes_to_octet(&value.address),
		signers: value.signers.iter().map(signer_to_transport).collect(),
	}
}

fn multisig_from_transport(value: gen::MultisigSigner) -> MultisigSigner {
	MultisigSigner {
		address: octet_to_bytes(value.address),
		signers: value
			.signers
			.into_iter()
			.map(signer_from_transport)
			.collect(),
	}
}

// --- Signatures -----------------------------------------------------------

fn signatures_to_transport(value: &Signatures) -> gen::Signatures {
	match value {
		Signatures::Single(bytes) => gen::Signatures::single(bytes_to_octet(bytes)),
		Signatures::Multiple(items) => gen::Signatures::multiple(items.iter().map(bytes_to_octet).collect()),
	}
}

fn signatures_from_transport(value: gen::Signatures) -> Signatures {
	match value {
		gen::Signatures::single(bytes) => Signatures::Single(octet_to_bytes(bytes)),
		gen::Signatures::multiple(items) => Signatures::Multiple(items.into_iter().map(octet_to_bytes).collect()),
	}
}

// --- Operation ------------------------------------------------------------

fn operation_to_transport(value: &Operation) -> gen::Operation {
	match value {
		Operation::Send(op) => gen::Operation::send(gen::SendOp {
			to: bytes_to_octet(&op.to),
			amount: bigint_to_integer(&op.amount),
			token: bytes_to_octet(&op.token),
			external: op.external.clone(),
		}),
		Operation::SetRep(op) => gen::Operation::setRep(gen::SetRepOp { to: bytes_to_octet(&op.to) }),
		Operation::SetInfo(op) => gen::Operation::setInfo(gen::SetInfoOp {
			name: op.name.clone(),
			description: op.description.clone(),
			metadata: op.metadata.clone(),
			default_permission: op.default_permission.as_ref().map(permissions_to_transport),
		}),
		Operation::ModifyPermissions(op) => gen::Operation::modifyPermissions(modify_permissions_to_transport(op)),
		Operation::CreateIdentifier(op) => gen::Operation::createIdentifier(create_identifier_to_transport(op)),
		Operation::TokenAdminSupply(op) => gen::Operation::tokenAdminSupply(gen::TokenAdminSupplyOp {
			amount: bigint_to_integer(&op.amount),
			method: bigint_to_integer(&op.method),
		}),
		Operation::TokenAdminModifyBalance(op) => {
			gen::Operation::tokenAdminModifyBalance(gen::TokenAdminModifyBalanceOp {
				token: bytes_to_octet(&op.token),
				amount: bigint_to_integer(&op.amount),
				method: bigint_to_integer(&op.method),
			})
		}
		Operation::Receive(op) => gen::Operation::receive(gen::ReceiveOp {
			amount: bigint_to_integer(&op.amount),
			token: bytes_to_octet(&op.token),
			from: bytes_to_octet(&op.from),
			exact: op.exact,
			forward: op.forward.as_ref().map(bytes_to_octet),
		}),
		Operation::ManageCertificate(op) => gen::Operation::manageCertificate(manage_certificate_to_transport(op)),
	}
}

fn operation_from_transport(value: gen::Operation) -> Operation {
	match value {
		gen::Operation::send(op) => Operation::Send(SendOp {
			to: octet_to_bytes(op.to),
			amount: integer_to_bigint(&op.amount),
			token: octet_to_bytes(op.token),
			external: op.external,
		}),
		gen::Operation::setRep(op) => Operation::SetRep(SetRepOp { to: octet_to_bytes(op.to) }),
		gen::Operation::setInfo(op) => Operation::SetInfo(SetInfoOp {
			name: op.name,
			description: op.description,
			metadata: op.metadata,
			default_permission: op.default_permission.map(permissions_from_transport),
		}),
		gen::Operation::modifyPermissions(op) => Operation::ModifyPermissions(modify_permissions_from_transport(op)),
		gen::Operation::createIdentifier(op) => Operation::CreateIdentifier(create_identifier_from_transport(op)),
		gen::Operation::tokenAdminSupply(op) => Operation::TokenAdminSupply(TokenAdminSupplyOp {
			amount: integer_to_bigint(&op.amount),
			method: integer_to_bigint(&op.method),
		}),
		gen::Operation::tokenAdminModifyBalance(op) => Operation::TokenAdminModifyBalance(TokenAdminModifyBalanceOp {
			token: octet_to_bytes(op.token),
			amount: integer_to_bigint(&op.amount),
			method: integer_to_bigint(&op.method),
		}),
		gen::Operation::receive(op) => Operation::Receive(ReceiveOp {
			amount: integer_to_bigint(&op.amount),
			token: octet_to_bytes(op.token),
			from: octet_to_bytes(op.from),
			exact: op.exact,
			forward: op.forward.map(octet_to_bytes),
		}),
		gen::Operation::manageCertificate(op) => Operation::ManageCertificate(manage_certificate_from_transport(op)),
	}
}

// --- ModifyPermissions ----------------------------------------------------

fn modify_permissions_to_transport(value: &ModifyPermissionsOp) -> gen::ModifyPermissionsOp {
	let principal = match &value.principal {
		ModifyPermissionsPrincipal::Account(bytes) => gen::ModifyPermissionsPrincipal::account(bytes_to_octet(bytes)),
		ModifyPermissionsPrincipal::Certificate(certificate) => {
			gen::ModifyPermissionsPrincipal::certificate(gen::CertificatePrincipal {
				hash: bytes_to_octet(&certificate.hash),
				account: bytes_to_octet(&certificate.account),
			})
		}
	};

	let permissions = match &value.permissions {
		PermissionsOrNull::Permissions(perms) => gen::PermissionsOrNull::permissions(permissions_to_transport(perms)),
		PermissionsOrNull::Null => gen::PermissionsOrNull::none(()),
	};

	gen::ModifyPermissionsOp {
		principal,
		method: bigint_to_integer(&value.method),
		permissions,
		target: value.target.as_ref().map(bytes_to_octet),
	}
}

fn modify_permissions_from_transport(value: gen::ModifyPermissionsOp) -> ModifyPermissionsOp {
	let principal = match value.principal {
		gen::ModifyPermissionsPrincipal::account(bytes) => ModifyPermissionsPrincipal::Account(octet_to_bytes(bytes)),
		gen::ModifyPermissionsPrincipal::certificate(cert) => {
			ModifyPermissionsPrincipal::Certificate(CertificatePrincipal {
				hash: octet_to_bytes(cert.hash),
				account: octet_to_bytes(cert.account),
			})
		}
	};

	let permissions = match value.permissions {
		gen::PermissionsOrNull::permissions(perms) => PermissionsOrNull::Permissions(permissions_from_transport(perms)),
		gen::PermissionsOrNull::none(()) => PermissionsOrNull::Null,
	};

	ModifyPermissionsOp {
		principal,
		method: integer_to_bigint(&value.method),
		permissions,
		target: value.target.map(octet_to_bytes),
	}
}

// --- CreateIdentifier -----------------------------------------------------

fn create_identifier_to_transport(value: &CreateIdentifierOp) -> gen::CreateIdentifierOp {
	gen::CreateIdentifierOp {
		identifier: bytes_to_octet(&value.identifier),
		multisig: value.multisig.as_ref().map(|args| gen::MultisigArguments {
			signers: args.signers.iter().map(bytes_to_octet).collect(),
			quorum: bigint_to_integer(&args.quorum),
		}),
	}
}

fn create_identifier_from_transport(value: gen::CreateIdentifierOp) -> CreateIdentifierOp {
	CreateIdentifierOp {
		identifier: octet_to_bytes(value.identifier),
		multisig: value.multisig.map(|args| MultisigArguments {
			signers: args.signers.into_iter().map(octet_to_bytes).collect(),
			quorum: integer_to_bigint(&args.quorum),
		}),
	}
}

// --- ManageCertificate ----------------------------------------------------

fn manage_certificate_to_transport(value: &ManageCertificateOp) -> gen::ManageCertificateOp {
	gen::ManageCertificateOp {
		method: bigint_to_integer(&value.method),
		certificate_or_hash: bytes_to_octet(&value.certificate_or_hash),
		intermediate_certificates: value
			.intermediate_certificates
			.as_ref()
			.map(|inter| match inter {
				IntermediateCertificates::Null => gen::IntermediateCertificates::none(()),
				IntermediateCertificates::Bundle(bundle) => {
					gen::IntermediateCertificates::bundle(bundle.iter().map(bytes_to_octet).collect())
				}
			}),
	}
}

fn manage_certificate_from_transport(value: gen::ManageCertificateOp) -> ManageCertificateOp {
	ManageCertificateOp {
		method: integer_to_bigint(&value.method),
		certificate_or_hash: octet_to_bytes(value.certificate_or_hash),
		intermediate_certificates: value.intermediate_certificates.map(|inter| match inter {
			gen::IntermediateCertificates::none(()) => IntermediateCertificates::Null,
			gen::IntermediateCertificates::bundle(bundle) => {
				IntermediateCertificates::Bundle(bundle.into_iter().map(octet_to_bytes).collect())
			}
		}),
	}
}

// --- Permissions ----------------------------------------------------------

fn permissions_to_transport(value: &Permissions) -> gen::Permissions {
	gen::Permissions { base: bigint_to_integer(&value.base), external: bigint_to_integer(&value.external) }
}

fn permissions_from_transport(value: gen::Permissions) -> Permissions {
	Permissions { base: integer_to_bigint(&value.base), external: integer_to_bigint(&value.external) }
}

// --- IntegerOrNull / OctetStringOrNull -----------------------------------

fn integer_or_null_to_transport(value: &IntegerOrNull) -> gen::IntegerOrNull {
	match value {
		IntegerOrNull::Value(bigint) => gen::IntegerOrNull::value(bigint_to_integer(bigint)),
		IntegerOrNull::Null => gen::IntegerOrNull::none(()),
	}
}

fn integer_or_null_from_transport(value: gen::IntegerOrNull) -> IntegerOrNull {
	match value {
		gen::IntegerOrNull::value(integer) => IntegerOrNull::Value(integer_to_bigint(&integer)),
		gen::IntegerOrNull::none(()) => IntegerOrNull::Null,
	}
}

fn octet_or_null_to_transport(value: &OctetStringOrNull) -> gen::OctetStringOrNull {
	match value {
		OctetStringOrNull::Value(bytes) => gen::OctetStringOrNull::value(bytes_to_octet(bytes)),
		OctetStringOrNull::Null => gen::OctetStringOrNull::none(()),
	}
}

fn octet_or_null_from_transport(value: gen::OctetStringOrNull) -> OctetStringOrNull {
	match value {
		gen::OctetStringOrNull::value(bytes) => OctetStringOrNull::Value(octet_to_bytes(bytes)),
		gen::OctetStringOrNull::none(()) => OctetStringOrNull::Null,
	}
}

// --- Primitive helpers ----------------------------------------------------

fn bigint_to_integer(value: &BigInt) -> Integer {
	Integer::from(value.clone())
}

fn integer_to_bigint(value: &Integer) -> BigInt {
	value.to_bigint().unwrap_or_default()
}

fn bytes_to_octet(value: impl AsRef<[u8]>) -> OctetString {
	OctetString::from(value.as_ref().to_vec())
}

fn octet_to_bytes(value: OctetString) -> Vec<u8> {
	value.to_vec()
}
