//! # Keetanetwork Contract Std
//!
//! Keeta-specific extensions for CosmWasm-compatible contracts.
//!
//! Contracts are ordinary CosmWasm contracts. Everything the CosmWasm
//! standard library already offers keeps working (`BankMsg`, `WasmMsg`,
//! bank and wasm queries, storage, submessages); this crate only adds the
//! pieces that are specific to Keeta:
//!
//! - [`KeetaMsg`]: actions a contract can take on the Keeta ledger beyond a
//!   plain bank send (send with an `external` memo, `SET_INFO`, issuing and
//!   administering native tokens).
//! - [`KeetaQuery`]: reads of Keeta ledger state (account info, token info,
//!   token address derivation).
//!
//! Conventions shared with the host engine:
//!
//! - Addresses are Keeta addresses (`keeta_…`).
//! - A bank `denom` is the Keeta address of the token account.
//! - Amounts are arbitrary-precision decimal strings ([`KeetaAmount`]),
//!   because Keeta token amounts can exceed `Uint256`.
//!
//! Enable the `cosmwasm` feature from contracts to get the
//! `cosmwasm_std::CustomMsg`/`CustomQuery` impls and the `requires_keeta`
//! capability export, which makes the host refuse to load a contract that
//! needs Keeta extensions on a chain that does not provide them.

#![deny(unsafe_code)]

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize};

/// Capability name a host must advertise to run contracts that use this crate.
pub const CAPABILITY: &str = "keeta";

/// An arbitrary-precision, non-negative integer amount, serialized as a
/// decimal string.
#[derive(Serialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct KeetaAmount(String);

impl KeetaAmount {
	/// Build an amount from a decimal string, rejecting anything that is not
	/// a non-empty run of ASCII digits.
	pub fn parse(value: impl Into<String>) -> Option<Self> {
		let value = value.into();
		if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		let trimmed = value.trim_start_matches('0');
		Some(Self(if trimmed.is_empty() {
			"0".into()
		} else {
			trimmed.into()
		}))
	}

	/// The decimal representation.
	pub fn as_str(&self) -> &str {
		&self.0
	}

	/// The amount as a `u128`, if it fits.
	pub fn to_u128(&self) -> Option<u128> {
		self.0.parse().ok()
	}
}

impl From<u128> for KeetaAmount {
	fn from(value: u128) -> Self {
		Self(value.to_string())
	}
}

impl From<u64> for KeetaAmount {
	fn from(value: u64) -> Self {
		Self(value.to_string())
	}
}

impl fmt::Display for KeetaAmount {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl<'de> Deserialize<'de> for KeetaAmount {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let raw = String::deserialize(deserializer)?;
		Self::parse(raw).ok_or_else(|| serde::de::Error::custom("amount must be a decimal string"))
	}
}

/// Keeta ledger actions a contract can request.
///
/// Every variant is performed *as the contract account*. Tokens issued with
/// [`KeetaMsg::CreateToken`] are identified by `(contract, subdenom)`; use
/// [`KeetaQuery::TokenAddress`] to learn the resulting token address.
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeetaMsg {
	/// `SEND` from the contract account, with an optional `external` memo
	/// (the reference field wallets and anchors use to correlate payments).
	Send {
		/// Recipient address
		to: String,
		/// Token address
		token: String,
		/// Amount to send
		amount: KeetaAmount,
		/// Optional `external` reference carried on the operation
		#[serde(default, skip_serializing_if = "Option::is_none")]
		external: Option<String>,
	},
	/// `SET_INFO` on the contract account.
	SetInfo {
		/// Account name (`[A-Z_]*`, at most 50 characters)
		name: String,
		/// Account description
		description: String,
		/// Base64 metadata
		metadata: String,
	},
	/// Issue a new native Keeta token administered by this contract.
	CreateToken {
		/// Contract-local name of the token, used to derive its address
		subdenom: String,
		/// Token name (`[A-Z_]*`)
		name: String,
		/// Token description
		description: String,
	},
	/// Mint `amount` of a token this contract created and send it to `to`.
	Mint {
		/// Contract-local name of the token
		subdenom: String,
		/// Recipient address
		to: String,
		/// Amount to mint
		amount: KeetaAmount,
	},
	/// Burn `amount` of a token this contract created, taken from the
	/// contract account's own balance.
	Burn {
		/// Contract-local name of the token
		subdenom: String,
		/// Amount to burn
		amount: KeetaAmount,
	},
}

/// Keeta ledger reads available to contracts.
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeetaQuery {
	/// `SET_INFO` fields of an account. Returns [`AccountInfoResponse`].
	AccountInfo {
		/// Account address
		account: String,
	},
	/// Address of the token `creator` issued under `subdenom`. Fails if the
	/// token has not been created: on-chain, a token's address depends on the
	/// block that creates it, so it cannot be predicted. Returns
	/// [`TokenAddressResponse`].
	TokenAddress {
		/// Creating contract address
		creator: String,
		/// Contract-local name of the token
		subdenom: String,
	},
	/// Supply and administration of a token. Returns [`TokenInfoResponse`].
	TokenInfo {
		/// Token address
		token: String,
	},
}

/// Response to [`KeetaQuery::AccountInfo`].
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AccountInfoResponse {
	/// Account name
	pub name: String,
	/// Account description
	pub description: String,
	/// Base64 metadata
	pub metadata: String,
}

/// Response to [`KeetaQuery::TokenAddress`].
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenAddressResponse {
	/// Token address
	pub token: String,
}

/// Response to [`KeetaQuery::TokenInfo`].
#[cfg_attr(feature = "cosmwasm", derive(schemars::JsonSchema))]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenInfoResponse {
	/// Token address
	pub token: String,
	/// Contract administering the token, if it was issued by a contract
	pub admin: Option<String>,
	/// Total supply
	pub supply: KeetaAmount,
}

#[cfg(feature = "cosmwasm")]
mod cosmwasm_impls {
	use cosmwasm_std::{CosmosMsg, CustomMsg, CustomQuery, QuerierWrapper, StdResult, Uint128};

	use super::*;

	impl CustomMsg for KeetaMsg {}
	impl CustomQuery for KeetaQuery {}

	impl From<KeetaMsg> for CosmosMsg<KeetaMsg> {
		fn from(msg: KeetaMsg) -> Self {
			CosmosMsg::Custom(msg)
		}
	}

	impl From<Uint128> for KeetaAmount {
		fn from(value: Uint128) -> Self {
			Self(value.to_string())
		}
	}

	/// Typed helpers over [`KeetaQuery`].
	pub trait KeetaQuerier {
		/// See [`KeetaQuery::AccountInfo`].
		fn keeta_account_info(&self, account: impl Into<String>) -> StdResult<AccountInfoResponse>;
		/// See [`KeetaQuery::TokenAddress`].
		fn keeta_token_address(&self, creator: impl Into<String>, subdenom: impl Into<String>) -> StdResult<String>;
		/// See [`KeetaQuery::TokenInfo`].
		fn keeta_token_info(&self, token: impl Into<String>) -> StdResult<TokenInfoResponse>;
	}

	impl KeetaQuerier for QuerierWrapper<'_, KeetaQuery> {
		fn keeta_account_info(&self, account: impl Into<String>) -> StdResult<AccountInfoResponse> {
			self.query(&KeetaQuery::AccountInfo { account: account.into() }.into())
		}

		fn keeta_token_address(&self, creator: impl Into<String>, subdenom: impl Into<String>) -> StdResult<String> {
			let response: TokenAddressResponse =
				self.query(&KeetaQuery::TokenAddress { creator: creator.into(), subdenom: subdenom.into() }.into())?;
			Ok(response.token)
		}

		fn keeta_token_info(&self, token: impl Into<String>) -> StdResult<TokenInfoResponse> {
			self.query(&KeetaQuery::TokenInfo { token: token.into() }.into())
		}
	}
}

#[cfg(feature = "cosmwasm")]
pub use cosmwasm_impls::KeetaQuerier;

/// Capability marker read by the host's static analysis. Exported from
/// every contract that links this crate with the `cosmwasm` feature.
#[cfg(all(feature = "cosmwasm", target_arch = "wasm32"))]
#[allow(unsafe_code)]
#[no_mangle]
extern "C" fn requires_keeta() {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn amount_parsing() {
		assert_eq!(KeetaAmount::parse("0042").unwrap().as_str(), "42");
		assert_eq!(KeetaAmount::parse("000").unwrap().as_str(), "0");
		assert!(KeetaAmount::parse("").is_none());
		assert!(KeetaAmount::parse("-1").is_none());
		assert!(KeetaAmount::parse("1.5").is_none());
		let huge = "1".repeat(150);
		assert_eq!(KeetaAmount::parse(huge.clone()).unwrap().as_str(), huge);
	}

	#[test]
	fn msg_wire_format() {
		let msg =
			KeetaMsg::Send { to: "keeta_a".into(), token: "keeta_t".into(), amount: 5u128.into(), external: None };
		let json = serde_json::to_string(&msg).unwrap();
		assert_eq!(json, r#"{"send":{"to":"keeta_a","token":"keeta_t","amount":"5"}}"#);
		assert!(serde_json::from_str::<KeetaAmount>(r#""-1""#).is_err());
	}
}
