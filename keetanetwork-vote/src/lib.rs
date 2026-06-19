//! # Keeta Network Vote and VoteStaple
//!
//! This crate models a representative's signed commitment that a set of
//! [`Block`](keetanetwork_block::Block)s should be inserted into the ledger
//! and the canonical bundle (`VoteStaple`) by which those commitments
//! propagate between operators.
//!
//! ## Concepts
//!
//! - **Vote**: a DER-encoded certificate-shaped commitment from an issuing
//!   representative covering one or more block hashes. Carries an optional
//!   fee schedule and a validity window.
//! - **Vote quote**: a non-binding vote whose fees field has `quote = true`.
//!   Used during fee negotiation; cannot be stapled or used to confirm
//!   blocks.
//! - **Possibly expired vote**: a vote that has been parsed and signature-
//!   verified but whose validity window may have ended. Surfaced for
//!   inspection paths that should not commit to inclusion.
//! - **Vote staple**: a zlib-compressed DER bundle of one or more votes
//!   together with the blocks they cover. The wire artifact transmitted
//!   between operators.
//!
//! ## Construction
//!
//! Use [`VoteBuilder`] or [`VoteQuoteBuilder`] to assemble and sign a vote
//! and [`VoteStapleBuilder`] to bundle votes and blocks into a staple. The
//! builders validate eagerly and surface configuration errors as
//! [`VoteError`] variants.
//!
//! ## Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use keetanetwork_account::GenericAccount;
//! use keetanetwork_account::doc_utils::create_ed25519_test_keys;
//! use keetanetwork_block::{AccountRef, BlockTime};
//! use keetanetwork_vote::{VoteBuilder, VoteError};
//!
//! # fn main() -> Result<(), VoteError> {
//! let (_, _, signer) = create_ed25519_test_keys(None);
//! let issuer: AccountRef = Arc::new(GenericAccount::Ed25519(signer));
//!
//! let from = BlockTime::from_unix_millis(1_000_000).expect("moment in range");
//! let to = BlockTime::from_unix_millis(2_000_000).expect("moment in range");
//!
//! let vote = VoteBuilder::new()
//!     .serial(1u64)
//!     .issuer(issuer.clone())
//!     .validity(from, to)
//!     .add_block(issuer.to_opening_hash())
//!     .build_signed(issuer.as_ref())?;
//!
//! assert!(!vote.as_bytes().is_empty());
//! # Ok(())
//! # }
//! ```
//!
//! ## Verification
//!
//! [`Vote::verify`] decodes wire bytes, rejects any non-canonical DER, and
//! checks the issuer's signature. [`VoteStaple::verify`] additionally
//! enforces the staple invariants (canonical ordering, agreed block set,
//! single-issuer constraint, uniform permanence) at a caller-supplied
//! moment.

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod builder;
mod cert;
mod error;
mod fee;
mod hash;
mod staple;
mod validation;
mod validity;
mod vote;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use builder::{VoteBuilder, VoteQuoteBuilder, VoteStapleBuilder};
pub use error::VoteError;
pub use fee::{Fee, Fees};
pub use hash::{Hashable, VoteBlockHash, VoteHash, VoteStapleHash};
pub use keetanetwork_block::{AccountRef, Amount};
pub use staple::VoteStaple;
pub use validation::{Network, ValidationConfig};
pub use validity::Validity;
pub use vote::{PossiblyExpiredVote, UnsignedVote, Vote, VoteQuote};
