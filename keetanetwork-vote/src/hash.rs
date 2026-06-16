//! Vote-domain hash.
//!
//! Three distinct types live here, each over a 32-byte SHA3-256 digest:
//!
//! * [`VoteHash`] - hash of a serialized vote (its certificate bytes).
//! * [`VoteStapleHash`] - hash of the canonical (uncompressed) vote staple bytes.
//! * [`VoteBlockHash`] - hash of the block hashes a vote/staple covers; the
//!   stable identity of the bundle, independent of which vote subset is
//!   included.

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt::{Display, Formatter, Result as FmtResult};
use core::str::FromStr;

use keetanetwork_crypto::error::CryptoError;
use keetanetwork_crypto::hash::{hash_default, BlockHash};

pub use keetanetwork_crypto::hash::Hashable;

macro_rules! digest_newtype {
	($(#[$meta:meta])* $name:ident) => {
		$(#[$meta])*
		#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
		pub struct $name([u8; 32]);

		impl $name {
			/// Borrow the digest as a fixed-size byte array.
			pub fn as_bytes(&self) -> &[u8; 32] {
				&self.0
			}
		}

		impl From<[u8; 32]> for $name {
			fn from(bytes: [u8; 32]) -> Self {
				Self(bytes)
			}
		}

		impl From<$name> for [u8; 32] {
			fn from(value: $name) -> Self {
				value.0
			}
		}

		impl AsRef<[u8]> for $name {
			fn as_ref(&self) -> &[u8] {
				&self.0
			}
		}

		impl TryFrom<&[u8]> for $name {
			type Error = CryptoError;

			fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
				let array: [u8; 32] = bytes.try_into()?;
				Ok(Self(array))
			}
		}

		impl Display for $name {
			fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
				write!(f, "{}", hex::encode_upper(self.0))
			}
		}

		impl FromStr for $name {
			type Err = CryptoError;

			fn from_str(s: &str) -> Result<Self, Self::Err> {
				let mut bytes = [0u8; 32];
				hex::decode_to_slice(s, &mut bytes)?;
				Ok(Self(bytes))
			}
		}
	};
}

digest_newtype!(
	/// Hash of an entire serialized vote certificate.
	VoteHash
);

digest_newtype!(
	/// Hash of a canonical, uncompressed vote staple body.
	VoteStapleHash
);

digest_newtype!(
	/// Hash of the block hashes covered by a vote or staple, independent of
	/// which vote subset is included.
	VoteBlockHash
);

impl VoteHash {
	/// Hash a serialized vote (the vote's wire bytes).
	pub fn of(vote_bytes: impl AsRef<[u8]>) -> Self {
		Self(hash_default(vote_bytes))
	}
}

impl VoteStapleHash {
	/// Hash an uncompressed vote staple body.
	pub fn of(staple_bytes: impl AsRef<[u8]>) -> Self {
		Self(hash_default(staple_bytes))
	}
}

impl VoteBlockHash {
	/// Compute a `VoteBlockHash` from the concatenation of the block hashes
	/// covered by a vote or staple.
	///
	/// The order of `block_hashes` is significant: the reference
	/// implementation hashes the buffers in the order they appear in the
	/// vote certificate.
	pub fn from_block_hashes<I>(block_hashes: I) -> Self
	where
		I: IntoIterator,
		I::Item: Borrow<BlockHash>,
	{
		let mut buffer: Vec<u8> = Vec::new();
		for hash in block_hashes {
			buffer.extend_from_slice(hash.borrow().as_bytes());
		}
		Self(hash_default(buffer))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_vote_hash_roundtrip() -> Result<(), CryptoError> {
		let h = VoteHash::of(b"hello");
		let parsed: VoteHash = h.to_string().parse()?;
		assert_eq!(parsed, h);
		Ok(())
	}

	#[test]
	fn test_vote_hash_and_staple_hash_share_byte_payload() {
		// Both newtypes wrap the network's default 32-byte digest, so the
		// underlying bytes coincide for identical input. Type-level
		// distinctness is enforced by the compiler, not by the digest.
		let bytes: &[u8] = b"abc";
		let v = VoteHash::of(bytes);
		let s = VoteStapleHash::of(bytes);
		assert_eq!(v.as_bytes(), s.as_bytes());
	}

	#[test]
	fn test_vote_block_hash_combines_in_order() {
		let h1 = BlockHash::from([1u8; 32]);
		let h2 = BlockHash::from([2u8; 32]);
		let in_order = VoteBlockHash::from_block_hashes([&h1, &h2]);
		let reversed = VoteBlockHash::from_block_hashes([&h2, &h1]);
		assert_ne!(in_order, reversed);
	}

	#[test]
	fn test_vote_block_hash_equivalent_to_concat_then_hash() {
		let h1 = BlockHash::from([3u8; 32]);
		let h2 = BlockHash::from([4u8; 32]);
		let combined = [h1.as_bytes().as_ref(), h2.as_bytes().as_ref()].concat();
		let direct = VoteBlockHash::from(hash_default(combined));
		assert_eq!(VoteBlockHash::from_block_hashes([&h1, &h2]), direct);
	}

	#[test]
	fn test_invalid_hash_parse() {
		assert!(matches!("zz".parse::<VoteHash>(), Err(CryptoError::InvalidInput)));
		assert!(matches!(VoteHash::try_from([0u8; 16].as_slice()), Err(CryptoError::InvalidKeySize)));
	}
}
