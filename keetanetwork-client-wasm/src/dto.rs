//! Serializable views of read results, with amounts rendered as decimal
//! strings and staples as hex so they survive the JS boundary losslessly.

use alloc::string::String;
use alloc::vec::Vec;

use keetanetwork_client::{AccountState, Acl, Certificate, HistoryEntry, LedgerChecksum, Representative, TokenBalance};
use serde::Serialize;

use crate::convert::amount_to_string;

/// A per-token balance: settled and pending amounts as decimal strings.
#[derive(Serialize)]
pub struct TokenBalanceView {
	pub token: String,
	pub balance: String,
	pub pending: String,
}

impl From<&TokenBalance> for TokenBalanceView {
	fn from(balance: &TokenBalance) -> Self {
		Self {
			token: balance.token.clone(),
			balance: amount_to_string(balance.balance.clone()),
			pending: amount_to_string(balance.pending.clone()),
		}
	}
}

/// A snapshot of an account's ledger state.
#[derive(Serialize)]
pub struct AccountStateView {
	pub representative: Option<String>,
	pub head: Option<String>,
	pub height: Option<String>,
	pub supply: Option<String>,
	pub balances: Vec<TokenBalanceView>,
}

impl From<&AccountState> for AccountStateView {
	fn from(state: &AccountState) -> Self {
		Self {
			representative: state.representative.clone(),
			head: state.head.clone(),
			height: state.height.clone().map(amount_to_string),
			supply: state.supply.clone().map(amount_to_string),
			balances: state.balances.iter().map(TokenBalanceView::from).collect(),
		}
	}
}

/// A history entry: the staple as hex plus its id and timestamp.
#[derive(Serialize)]
pub struct HistoryEntryView {
	pub staple: String,
	pub id: Option<String>,
	pub timestamp: Option<String>,
}

impl From<&HistoryEntry> for HistoryEntryView {
	fn from(entry: &HistoryEntry) -> Self {
		Self { staple: hex::encode(entry.staple.as_bytes()), id: entry.id.clone(), timestamp: entry.timestamp.clone() }
	}
}

/// A representative and its voting weight.
#[derive(Serialize)]
pub struct RepresentativeView {
	pub account: String,
	pub weight: String,
	pub api_url: Option<String>,
}

impl From<&Representative> for RepresentativeView {
	fn from(rep: &Representative) -> Self {
		Self {
			account: rep.account.clone(),
			weight: amount_to_string(rep.weight.clone()),
			api_url: rep.api_url.clone(),
		}
	}
}

/// A point-in-time ledger checksum.
#[derive(Serialize)]
pub struct LedgerChecksumView {
	pub checksum: String,
	pub moment: Option<String>,
	pub moment_range: Option<f64>,
}

impl From<&LedgerChecksum> for LedgerChecksumView {
	fn from(checksum: &LedgerChecksum) -> Self {
		Self {
			checksum: amount_to_string(checksum.checksum.clone()),
			moment: checksum.moment.clone(),
			moment_range: checksum.moment_range,
		}
	}
}

/// An access-control entry.
#[derive(Serialize)]
pub struct AclView {
	pub principal: Option<String>,
	pub entity: Option<String>,
	pub target: Option<String>,
	pub permissions: Vec<String>,
}

impl From<&Acl> for AclView {
	fn from(acl: &Acl) -> Self {
		Self {
			principal: acl.principal.clone(),
			entity: acl.entity.clone(),
			target: acl.target.clone(),
			permissions: acl.permissions.clone(),
		}
	}
}

/// A certificate and its intermediate chain.
#[derive(Serialize)]
pub struct CertificateView {
	pub certificate: String,
	pub intermediates: Vec<String>,
}

impl From<&Certificate> for CertificateView {
	fn from(certificate: &Certificate) -> Self {
		Self { certificate: certificate.certificate.clone(), intermediates: certificate.intermediates.clone() }
	}
}
