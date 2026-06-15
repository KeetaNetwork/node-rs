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
//! ```no_run
//! use keetanetwork_block::{AccountRef, BlockHash, BlockTime};
//! use keetanetwork_vote::{VoteBuilder, VoteError};
//!
//! # fn build(issuer: AccountRef, block: BlockHash, from: BlockTime, to: BlockTime) -> Result<(), VoteError> {
//! let vote = VoteBuilder::new()
//!     .serial(1u64)
//!     .issuer(issuer.clone())
//!     .validity(from, to)
//!     .add_block(block)
//!     .build_signed(issuer.as_ref())?;
//! let _bytes: &[u8] = vote.as_bytes();
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

mod builder;
mod cert;
mod error;
mod extension;
mod fee;
mod hash;
mod oids;
mod staple;
mod validation;
mod validity;
mod vote;
mod wire;

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
