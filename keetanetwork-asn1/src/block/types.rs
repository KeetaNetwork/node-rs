//! Public domain types for the keetanetwork block transport format.
//!
//! See `keetanetwork-asn1/asn1/block.asn` for the canonical schema and
//! [`crate::block::codec`] for the byte-level encode/decode entry points.

use crate::Asn1Time;
use num_bigint::BigInt;

/// Pair of base/external permission bitmasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
	pub base: BigInt,
	pub external: BigInt,
}

/// Optional [`Permissions`] slot in MODIFY_PERMISSIONS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionsOrNull {
	Permissions(Permissions),
	Null,
}

/// Certificate-bound principal of a permissions grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePrincipal {
	pub hash: Vec<u8>,
	pub account: Vec<u8>,
}

/// Principal of a permissions grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModifyPermissionsPrincipal {
	Account(Vec<u8>),
	Certificate(CertificatePrincipal),
}

/// Multisig arguments carried inside a `CREATE_IDENTIFIER` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigArguments {
	pub signers: Vec<Vec<u8>>,
	pub quorum: BigInt,
}

/// Optional intermediate-certificate slot in `MANAGE_CERTIFICATE` operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntermediateCertificates {
	/// Encoded as `NULL`.
	Null,
	/// Encoded as `SEQUENCE OF OCTET STRING`.
	Bundle(Vec<Vec<u8>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendOp {
	pub to: Vec<u8>,
	pub amount: BigInt,
	pub token: Vec<u8>,
	pub external: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetRepOp {
	pub to: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfoOp {
	pub name: String,
	pub description: String,
	pub metadata: String,
	pub default_permission: Option<Permissions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModifyPermissionsOp {
	pub principal: ModifyPermissionsPrincipal,
	pub method: BigInt,
	pub permissions: PermissionsOrNull,
	pub target: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateIdentifierOp {
	pub identifier: Vec<u8>,
	pub multisig: Option<MultisigArguments>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAdminSupplyOp {
	pub amount: BigInt,
	pub method: BigInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAdminModifyBalanceOp {
	pub token: Vec<u8>,
	pub amount: BigInt,
	pub method: BigInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveOp {
	pub amount: BigInt,
	pub token: Vec<u8>,
	pub from: Vec<u8>,
	pub exact: bool,
	pub forward: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageCertificateOp {
	pub method: BigInt,
	pub certificate_or_hash: Vec<u8>,
	pub intermediate_certificates: Option<IntermediateCertificates>,
}

/// Operation discriminated on the transport by context tag `[0..=8] EXPLICIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
	Send(SendOp),
	SetRep(SetRepOp),
	SetInfo(SetInfoOp),
	ModifyPermissions(ModifyPermissionsOp),
	CreateIdentifier(CreateIdentifierOp),
	TokenAdminSupply(TokenAdminSupplyOp),
	TokenAdminModifyBalance(TokenAdminModifyBalanceOp),
	Receive(ReceiveOp),
	ManageCertificate(ManageCertificateOp),
}

/// A multisig signer-tree node. `signers` references [`Signer`] recursively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigSigner {
	pub address: Vec<u8>,
	pub signers: Vec<Signer>,
}

/// Block signer slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signer {
	/// `NULL` placeholder used by V2 when the signer equals the account.
	Empty,
	/// A single account public key.
	Single(Vec<u8>),
	/// A multisig tree.
	Multisig(MultisigSigner),
}

/// Block signature(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signatures {
	Single(Vec<u8>),
	Multiple(Vec<Vec<u8>>),
}

/// Optional-or-`NULL` `INTEGER` wrapper used by V1 fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerOrNull {
	Value(BigInt),
	Null,
}

/// Optional-or-`NULL` `OCTET STRING` wrapper used by V1 fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OctetStringOrNull {
	Value(Vec<u8>),
	Null,
}

/// V1 block envelope (legacy single-signer transport format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV1 {
	pub version: BigInt,
	pub network: BigInt,
	pub subnet: IntegerOrNull,
	pub idempotent: Option<Vec<u8>>,
	pub date: Asn1Time,
	pub signer: Vec<u8>,
	pub account: OctetStringOrNull,
	pub previous: Vec<u8>,
	pub operations: Vec<Operation>,
	pub signature: Option<Vec<u8>>,
}

/// V2 block body, wrapped on the transport by `[1] EXPLICIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV2Body {
	pub network: BigInt,
	pub subnet: Option<BigInt>,
	pub idempotent: Option<Vec<u8>>,
	pub date: Asn1Time,
	pub purpose: BigInt,
	pub account: Vec<u8>,
	pub signer: Signer,
	pub previous: Vec<u8>,
	pub operations: Vec<Operation>,
	pub signatures: Option<Signatures>,
}

/// V2 block envelope (`[1] EXPLICIT` of [`BlockV2Body`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockV2(pub BlockV2Body);

/// Either a V1 or V2 transport block; the discriminant on the transport is the
/// outer tag (`SEQUENCE` for V1, `[1] EXPLICIT` for V2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
	V1(BlockV1),
	V2(BlockV2),
}
