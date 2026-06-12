//! Block signer field: a single account or a nested multisig tree.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use keetanetwork_account::GenericAccount;

/// Shared reference to an account.
///
/// Accounts are not cloneable (they may hold private keys), so block types
/// share them via [`Arc`].
pub type AccountRef = Arc<GenericAccount>;

/// The signer field of a block: a single keyed account, or a multisig
/// address with the signers acting on its behalf (which may themselves be
/// nested multisig entries).
#[derive(Debug, Clone)]
pub enum Signer {
	/// A single keyed account.
	Single(AccountRef),
	/// A multisig address with its member signers.
	Multisig {
		/// The multisig address holding the necessary permissions.
		address: AccountRef,
		/// Signers acting on behalf of the multisig address.
		signers: Vec<Signer>,
	},
}

impl Signer {
	/// The account this signer field represents (the multisig address for
	/// multisig signers).
	pub fn principal(&self) -> &AccountRef {
		match self {
			Signer::Single(account) => account,
			Signer::Multisig { address, .. } => address,
		}
	}

	/// The keyed accounts which must produce signatures, in signature
	/// order: depth-first pre-order with duplicates removed.
	pub fn required_signers(&self) -> Vec<AccountRef> {
		let mut queue: VecDeque<&Signer> = VecDeque::new();
		queue.push_back(self);

		let mut visited: HashSet<String> = HashSet::new();
		let mut out: Vec<AccountRef> = Vec::new();

		while let Some(current) = queue.pop_front() {
			match current {
				Signer::Single(account) => {
					if visited.insert(account.to_string()) {
						out.push(account.clone());
					}
				}
				Signer::Multisig { signers, .. } => {
					for child in signers.iter().rev() {
						queue.push_front(child);
					}
				}
			}
		}

		out
	}
}

impl From<AccountRef> for Signer {
	fn from(account: AccountRef) -> Self {
		Signer::Single(account)
	}
}

impl From<GenericAccount> for Signer {
	fn from(account: GenericAccount) -> Self {
		Signer::Single(Arc::new(account))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keetanetwork_account::{Account, Accountable, KeyED25519, KeyPairType, Keyable};
	use keetanetwork_crypto::prelude::IntoSecret;

	fn ed25519_account(seed_byte: u8) -> Account<KeyED25519> {
		let seed = [seed_byte; 32].into_secret();
		Account::<KeyED25519>::try_from(Accountable::KeyAndType(Keyable::Seed((seed, 0)), KeyPairType::ED25519))
			.unwrap()
	}

	fn account(seed_byte: u8) -> AccountRef {
		Arc::new(GenericAccount::Ed25519(ed25519_account(seed_byte)))
	}

	fn multisig_address(seed_byte: u8) -> AccountRef {
		Arc::new(
			ed25519_account(seed_byte)
				.generate_identifier(KeyPairType::MULTISIG, None, 0)
				.unwrap(),
		)
	}

	#[test]
	fn test_single_required_signers() {
		let signer = Signer::from(account(1));
		let required = signer.required_signers();
		assert_eq!(required.len(), 1);
		assert_eq!(required[0].to_string(), account(1).to_string());
	}

	#[test]
	fn test_multisig_preorder_flatten() {
		let nested = Signer::Multisig {
			address: multisig_address(9),
			signers: vec![Signer::from(account(3)), Signer::from(account(4))],
		};
		let signer = Signer::Multisig {
			address: multisig_address(8),
			signers: vec![Signer::from(account(1)), nested, Signer::from(account(2))],
		};

		let required: Vec<String> = signer
			.required_signers()
			.iter()
			.map(|a| a.to_string())
			.collect();
		let expected: Vec<String> = [1u8, 3, 4, 2]
			.iter()
			.map(|seed_byte| account(*seed_byte).to_string())
			.collect();
		assert_eq!(required, expected);
	}

	#[test]
	fn test_duplicate_signers_deduplicated() {
		let signer = Signer::Multisig {
			address: multisig_address(8),
			signers: vec![
				Signer::from(account(1)),
				Signer::Multisig {
					address: multisig_address(9),
					signers: vec![Signer::from(account(1)), Signer::from(account(2))],
				},
			],
		};

		let required = signer.required_signers();
		assert_eq!(required.len(), 2);
	}

	#[test]
	fn test_principal() {
		let address = multisig_address(7);
		let signer = Signer::Multisig { address: address.clone(), signers: vec![Signer::from(account(1))] };
		assert_eq!(signer.principal().to_string(), address.to_string());
	}
}
