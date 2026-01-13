//! # Keetanetwork Block
//!
//! This crate provides block structure and operations for the Keetanetwork blockchain.

#![cfg_attr(not(feature = "std"), no_std)]

mod types;

// KeetaBlock requires alloc (uses Vec<Operation>)
#[cfg(any(feature = "alloc", feature = "std"))]
pub use types::KeetaBlock;

pub use types::{
	// Enums
	AdjustMethod,
	AdjustMethodRelative,
	// Block types
	BlockHeader,
	BlockPurpose,
	BlockVersion,
	// Operation structs
	CancelSwapOp,
	CreateIdentifierArgs,
	CreateIdentifierOp,
	// Supporting types
	FeeDetails,
	FeeDetailsWithRecipient,
	ManageCertificateOp,
	MatchSwapOp,
	ModifyPermissionsOp,
	// Operation enum
	Operation,
	Permission,
	ReceiveOp,
	SendOp,
	SetInfoOp,
	SetRepOp,
	TokenAdminSupplyOp,
	TokenAdminModifyBalanceOp,
	TokenValue,
};
