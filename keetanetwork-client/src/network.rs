//! Static registry of the well-known KeetaNet networks.
//!
//! Maps each network to its identifier, initial trusted account,
//! representative endpoints, and publish-aid URL.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use keetanetwork_account::{Account, Accountable, GenericAccount, KeyECDSASECP256K1, KeyPairType, Keyable};
use keetanetwork_block::AccountRef;
use num_bigint::BigInt;

use crate::error::ClientError;
use crate::rep::RepEndpoint;

/// Placeholder voting weight seeded into registry representatives; the first
/// weight refresh replaces it with on-ledger voting power.
const SEED_WEIGHT: u8 = 1;

/// The deterministic seed backing the `dev` network's accounts (hex, 32 bytes).
const DEV_SEED: &str = "1000000000000000000000000000000000000000000000000000000000000000";

/// Derivation index used for the `dev` network's initial trusted account.
const DEV_TRUSTED_INDEX: u32 = 0xffff_ffff;

/// A well-known KeetaNet network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
	/// The production network.
	Main,
	/// The staging network.
	Staging,
	/// The public test network.
	Test,
	/// The development network (deterministic, seed-derived accounts).
	Dev,
}

impl Network {
	/// The network identifier stamped onto blocks for this network.
	pub fn id(self) -> BigInt {
		let id: u32 = match self {
			Network::Main => 0x5382,
			Network::Staging => 0x0053_8201,
			Network::Test => 0x5445_5354,
			Network::Dev => 0x0044_4556,
		};
		BigInt::from(id)
	}

	/// The lowercase alias used in URLs and string parsing.
	pub fn alias(self) -> &'static str {
		match self {
			Network::Main => "main",
			Network::Staging => "staging",
			Network::Test => "test",
			Network::Dev => "dev",
		}
	}

	/// The default configuration for this network: its identifier, initial
	/// trusted account, representative endpoints, and publish-aid URL.
	///
	/// # Errors
	///
	/// - [`ClientError::Account`] -- a registry key string (or, for
	///   [`Network::Dev`], a seed-derived account) fails to parse.
	///
	/// # Examples
	///
	/// ```
	/// use keetanetwork_client::Network;
	///
	/// let config = Network::Test.config()?;
	/// assert_eq!(config.representatives.len(), 4);
	/// # Ok::<(), keetanetwork_client::ClientError>(())
	/// ```
	pub fn config(self) -> Result<NetworkConfig, ClientError> {
		let (initial_trusted_account, representatives) = self.accounts_and_reps()?;
		Ok(NetworkConfig {
			network: self,
			network_id: self.id(),
			initial_trusted_account,
			representatives,
			publish_aid_url: self.publish_aid_url(),
		})
	}

	/// Resolve the initial trusted account and representative endpoints,
	/// deriving the `dev` accounts from the seed and parsing the others from
	/// their published key strings.
	fn accounts_and_reps(self) -> Result<(AccountRef, Vec<RepEndpoint>), ClientError> {
		match self {
			Network::Dev => {
				let trusted = account_from_seed(DEV_TRUSTED_INDEX)?;
				let mut reps = Vec::with_capacity(4);
				for index in 1u32..=4 {
					let account = account_from_seed(index)?;
					reps.push(RepEndpoint::new(self.rep_api_url(index), account, SEED_WEIGHT));
				}
				Ok((trusted, reps))
			}
			Network::Main => self.keyed_reps(MAIN_TRUSTED, &MAIN_REPS),
			Network::Staging => self.keyed_reps(STAGING_TRUSTED, &STAGING_REPS),
			Network::Test => self.keyed_reps(TEST_TRUSTED, &TEST_REPS),
		}
	}

	/// Build the trusted account and representatives from published key
	/// strings, numbering the API endpoints from one.
	fn keyed_reps(self, trusted: &str, keys: &[&str]) -> Result<(AccountRef, Vec<RepEndpoint>), ClientError> {
		let trusted = account_from_key(trusted)?;
		let mut reps = Vec::with_capacity(keys.len());
		for (offset, key) in keys.iter().enumerate() {
			let rep_id = u32::try_from(offset).unwrap_or(0).saturating_add(1);
			let account = account_from_key(key)?;
			reps.push(RepEndpoint::new(self.rep_api_url(rep_id), account, SEED_WEIGHT));
		}

		Ok((trusted, reps))
	}

	/// The API endpoint for representative `rep_id`. Production networks carry
	/// a `network` infix; `dev` does not.
	fn rep_api_url(self, rep_id: u32) -> String {
		let alias = self.alias();
		match self {
			Network::Dev => format!("https://rep{rep_id}.{alias}.api.keeta.com/api"),
			_ => format!("https://rep{rep_id}.{alias}.network.api.keeta.com/api"),
		}
	}

	/// The publish-aid URL. `test` carries a `network` infix; the others do
	/// not.
	fn publish_aid_url(self) -> String {
		let alias = self.alias();
		match self {
			Network::Test => format!("https://publish-aid.{alias}.network.api.keeta.com/api/publish"),
			_ => format!("https://publish-aid.{alias}.api.keeta.com/api/publish"),
		}
	}
}

impl FromStr for Network {
	type Err = ClientError;

	/// Parse a network from its lowercase [`alias`](Network::alias)
	/// (`main`, `staging`, `test`, `dev`).
	///
	/// # Errors
	///
	/// - [`ClientError::UnsupportedNetwork`] -- the value is not a known alias.
	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value {
			"main" => Ok(Network::Main),
			"staging" => Ok(Network::Staging),
			"test" => Ok(Network::Test),
			"dev" => Ok(Network::Dev),
			_ => Err(ClientError::UnsupportedNetwork),
		}
	}
}

impl fmt::Display for Network {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.alias())
	}
}

/// The resolved default configuration for a [`Network`].
#[derive(Clone, Debug)]
pub struct NetworkConfig {
	/// The network this configuration describes.
	pub network: Network,
	/// The network identifier stamped onto blocks.
	pub network_id: BigInt,
	/// The account trusted to bootstrap and govern the network.
	pub initial_trusted_account: AccountRef,
	/// The default representative endpoints for the network.
	pub representatives: Vec<RepEndpoint>,
	/// The publish-aid endpoint for server-assisted publishing.
	pub publish_aid_url: String,
}

/// Parse a published key string into an account reference.
fn account_from_key(key: &str) -> Result<AccountRef, ClientError> {
	let account = GenericAccount::from_str(key).map_err(|source| ClientError::Account { source })?;
	Ok(Arc::new(account))
}

/// Derive a `dev`-network account from the deterministic seed at `index`.
fn account_from_seed(index: u32) -> Result<AccountRef, ClientError> {
	let keyable = Keyable::from((DEV_SEED, index));
	let account = Account::<KeyECDSASECP256K1>::try_from(Accountable::KeyAndType(keyable, KeyPairType::ECDSASECP256K1))
		.map_err(|source| ClientError::Account { source })?;
	Ok(Arc::new(GenericAccount::EcdsaSecp256k1(account)))
}

const MAIN_TRUSTED: &str = "keeta_aabk62tezl4whordlviamlx3zrdgux6lk63cghay45vkzdatyemzvqqjuj5resa";
const MAIN_REPS: [&str; 4] = [
	"keeta_aabwip6zeo2fnzfxp5hssrrqtascs2277w2zk7vqd6d3k3m4dkt2flcbca2mqki",
	"keeta_aabvmwxttv4q56gbfveighwfwp3yvitlrdfsacic3ckqc7lqelsspvmhc7oldmq",
	"keeta_aabwqf5fnta4t2v2atieis545b3rqoq6z7x5w3geugiilqlz5jdsb5og2rmxvdq",
	"keeta_aablpogflko72eusdhuuqgsto2rwcvy2m5mo5snmvrmbacz3qczwjtwpmzf5ufq",
];

const STAGING_TRUSTED: &str = "keeta_aabhtbqmg7whgpvbgii6twdjlyq5vlrtwaa47nb5b2gj6an5kvjbwvvw2mdwjjy";
const STAGING_REPS: [&str; 4] = [
	"keeta_aabaagdrwrwnkzox4u3qh6uukre6lckax6kb5fwyxd4vtpua6vrjc6nuhb75fji",
	"keeta_aabgizanf4agmioyrswbg4wsl7nmjlrakwd4piuks7cqagfccnxc2fscm25hw7i",
	"keeta_aab2gw2zmtazqgtromyfmhjn5h67ep23676zq62obgtqaw65x5l5krn252w57ma",
	"keeta_aabue4mdj22i5o6774tlszcxy2sxyvpninbm54nfhxn6dkmsvtryd7oha4bzh2i",
];

const TEST_TRUSTED: &str = "keeta_aabmvemiol5wrs67e4rfiyibopwav4e77sleiqaqvbdprbuxrifn7fgg4cchhia";
const TEST_REPS: [&str; 4] = [
	"keeta_aabi4bd3f7jrt67mxcq44ozj65bh4bp2mygmrkedxggu2rxwn2ztuw3b6exivbq",
	"keeta_aabf7dz5asq2n2lrldct33x2ww65cophxp7egfiixbb7tbyat5r3kcbcez7ftpi",
	"keeta_aab3cxegizwhtim3zlyuwjhiqd5ikkhxg42smhwc3wx6yn7ep2t6lwo6emvw4wa",
	"keeta_aabznoicrzvte6ql5rxbgugmfrjqubbnjuo5l6ivopowy4rpkqgs5fco3oaezcq",
];

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn alias_round_trips_through_from_str() -> Result<(), ClientError> {
		for network in [Network::Main, Network::Staging, Network::Test, Network::Dev] {
			assert_eq!(Network::from_str(network.alias())?, network, "alias must parse back to its network");
		}
		Ok(())
	}

	#[test]
	fn unknown_alias_is_unsupported() {
		assert!(matches!(Network::from_str("mainnet"), Err(ClientError::UnsupportedNetwork)));
	}

	#[test]
	fn network_ids_match_reference() {
		assert_eq!(Network::Main.id(), BigInt::from(0x5382u32));
		assert_eq!(Network::Staging.id(), BigInt::from(0x0053_8201u32));
		assert_eq!(Network::Test.id(), BigInt::from(0x5445_5354u32));
		assert_eq!(Network::Dev.id(), BigInt::from(0x0044_4556u32));
	}

	#[test]
	fn keyed_config_parses_four_reps_and_trusted_account() -> Result<(), ClientError> {
		let config = Network::Test.config()?;

		assert_eq!(config.representatives.len(), 4, "the test network publishes four representatives");
		assert_eq!(config.initial_trusted_account.to_string(), TEST_TRUSTED, "trusted account must parse verbatim");
		assert_eq!(
			config.representatives[0].api_url(),
			"https://rep1.test.network.api.keeta.com/api",
			"production rep URLs carry the network infix"
		);
		assert_eq!(
			config.publish_aid_url, "https://publish-aid.test.network.api.keeta.com/api/publish",
			"the test publish-aid URL carries the network infix"
		);
		Ok(())
	}

	#[test]
	fn every_network_config_resolves() -> Result<(), ClientError> {
		for network in [Network::Main, Network::Staging, Network::Test, Network::Dev] {
			let config = network.config()?;
			assert_eq!(config.representatives.len(), 4, "every network must publish four representatives");
		}
		Ok(())
	}

	#[test]
	fn dev_config_derives_reps_from_seed() -> Result<(), ClientError> {
		let config = Network::Dev.config()?;

		assert_eq!(config.representatives.len(), 4, "the dev network derives four representatives");
		assert_eq!(
			config.representatives[0].api_url(),
			"https://rep1.dev.api.keeta.com/api",
			"dev rep URLs omit the network infix"
		);
		assert_eq!(
			config.initial_trusted_account.to_string(),
			account_from_seed(DEV_TRUSTED_INDEX)?.to_string(),
			"the dev trusted account is derived deterministically from the seed"
		);
		Ok(())
	}
}
