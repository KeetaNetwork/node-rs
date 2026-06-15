//! # Keetanetwork Block
//!
//! Block structure, operations, signing and validation for the
//! Keetanetwork blockchain.
//!
//! # Example
//!
//! ```
//! use keetanetwork_account::{Account, Accountable, GenericAccount, KeyED25519, KeyPairType, Keyable};
//! use keetanetwork_block::{AccountRef, Block, BlockBuilder, Operation, Receive};
//! use keetanetwork_crypto::hash::Hashable;
//! use keetanetwork_crypto::prelude::IntoSecret;
//!
//! let seed = [7u8; 32].into_secret();
//! let account = Account::<KeyED25519>::try_from(Accountable::KeyAndType(
//!     Keyable::Seed((seed, 0)),
//!     KeyPairType::ED25519,
//! ))?;
//! let token = account.generate_identifier(KeyPairType::TOKEN, None, 0)?;
//! let account = AccountRef::from(GenericAccount::Ed25519(account));
//!
//! let unsigned = BlockBuilder::default()
//!     .with_network(0u8)
//!     .with_account(account.clone())
//!     .as_opening()
//!     .with_operation(Receive {
//!         amount: 10u64.into(),
//!         token: token.into(),
//!         from: account.clone(),
//!         exact: false,
//!         forward: None,
//!     })
//!     .build()?;
//!
//! let block = unsigned.sign()?;
//! let decoded = Block::try_from(block.to_bytes())?;
//! assert_eq!(decoded.hash(), block.hash());
//! # Ok::<(), keetanetwork_block::BlockError>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod account_util;
mod amount;
mod block;
mod builder;
mod error;
mod operation;
mod permissions;
mod signer;
mod time;
mod transport;
mod validation;

#[cfg(test)]
mod testing;

pub use amount::Amount;
pub use block::{Block, BlockData, BlockPurpose, BlockVersion, Signature, UnsignedBlock};
pub use builder::BlockBuilder;
pub use error::{BlockError, BlockField, InfoField};
pub use operation::{
	AdjustMethod, CertificateDer, CertificateOrHash, CreateIdentifier, IdentifierCreateArguments,
	IntermediateCertificates, ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal,
	MultisigCreateArguments, Operation, OperationType, Receive, Send, SetInfo, SetRep, TokenAdminModifyBalance,
	TokenAdminSupply,
};
pub use permissions::{BaseFlag, BaseSet, ExternalSet, GroupKind, PermissionGroup, Permissions};
pub use signer::{AccountRef, Signer};
pub use time::BlockTime;
pub use validation::{Network, TextRule, TextRuleViolation, ValidationConfig};

// Re-exports of the core hash types defined alongside the hashing
// primitives in `keetanetwork-crypto`.
pub use keetanetwork_crypto::hash::{BlockHash, Hashable};
