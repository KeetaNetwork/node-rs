//! JS `PendingAccount`: a handle to an identifier created during a build.

use keetanetwork_client::PendingAccount as Core;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::convert::{client_error, JsResult};

/// A not-yet-derived identifier returned by
/// [`Builder::generate_identifier`](crate::builder). Resolves to a concrete
/// [`Account`] once the creating builder has been built.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PendingAccount {
	inner: Core,
}

#[wasm_bindgen]
impl PendingAccount {
	/// The derived identifier as an [`Account`]. Errors with
	/// `UNRESOLVED_IDENTIFIER` until the creating builder has been built.
	pub fn get(&self) -> JsResult<Account> {
		let account = self.inner.get().map_err(client_error)?;
		Ok(Account::from(account))
	}
}

impl From<Core> for PendingAccount {
	fn from(inner: Core) -> Self {
		Self { inner }
	}
}
