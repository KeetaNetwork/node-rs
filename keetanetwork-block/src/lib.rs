//! # Keetanetwork Block
//!
//! This crate provides block structure and operations for the Keetanetwork blockchain.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod metadata;
mod parse;
pub mod permissions;
mod types;

pub use parse::extract_operations_slice;

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
