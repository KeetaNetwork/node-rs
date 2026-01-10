//! # Keetanetwork Block
//!
//! This crate provides block structure and operations for the Keetanetwork blockchain.

#![cfg_attr(not(feature = "std"), no_std)]

mod types;

// KeetaBlock requires alloc (uses Vec<Operation>)
#[cfg(any(feature = "alloc", feature = "std"))]
pub use types::KeetaBlock;

pub use types::{
    // Address validation
    algo_prefix, is_valid_address,
    // Block types
    BlockHeader, BlockPurpose, BlockVersion,
    // Operation enum
    Operation,
    // Operation structs
    CancelSwapOp, CreateIdentifierOp, CreateIdentifierArgs, ManageCertificateOp, MatchSwapOp,
    ModifyPermissionsOp, ReceiveOp, SendOp, SetInfoOp, SetRepOp, TokenAdminSupplyOp,
    TokenModifyBalanceOp,
    // Supporting types
    FeeDetails, FeeDetailsWithRecipient, Permission, TokenValue,
    // Enums
    AdjustMethod, AdjustMethodRelative,
};
