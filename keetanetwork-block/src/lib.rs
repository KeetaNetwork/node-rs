//! # Keetanetwork Block
//!
//! This crate provides block structure and operations for the Keetanetwork blockchain.

#![cfg_attr(not(feature = "std"), no_std)]

mod types;

#[cfg(any(feature = "alloc", feature = "std"))]
mod block;

// Types that require alloc (use Vec)
#[cfg(any(feature = "alloc", feature = "std"))]
pub use types::{
	// Vote/Certificate types
	AlgorithmIdentifier,
	CertificateExtensionWrapper,
	FeeData,
	HashData,
	// Block types
	KeetaBlock,
	KeetaBlockBuilder,
	SubjectPublicKeyInfo,
	TbsCertificate,
	Validity,
	Vote,
	VoteStaple,
};

pub use types::{
	// Enums
	AdjustMethod,
	AdjustMethodRelative,
	// Block types
	BlockHeader,
	BlockPurpose,
	BlockVersion,
	// Type aliases (maps to der types or raw bytes)
	Bytes,
	// Operation structs
	CancelSwapOp,
	CreateIdentifierArgs,
	CreateIdentifierOp,
	// Supporting types
	FeeRate,
	FeeValue,
	FeeValueWithRecipient,
	Int,
	ManageCertificateOp,
	MatchSwapOp,
	ModifyPermissionsOp,
	MultisigArgs,
	// Value-or-none wrapper (like Option but NULL has meaning)
	NullOr,
	// Operation enum
	Operation,
	Permission,
	ReceiveOp,
	SendOp,
	SetInfoOp,
	SetRepOp,
	Str,
	SwapArgs,
	TokenAdminModifyBalanceOp,
	TokenAdminSupplyOp,
	TokenRate,
	TokenValue,
};
