//! JS `Permissions` and `PermissionChange`: inputs for MODIFY_PERMISSIONS.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use keetanetwork_block::{ModifyPermissions, ModifyPermissionsPrincipal, Permissions as CorePermissions};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::account::Account;
use crate::convert::{coded_error, parse_adjust_method, parse_base_flag, parse_hash32, JsResult};

/// A permission set: well-known base flags plus optional external bit offsets.
#[wasm_bindgen]
#[derive(Clone)]
pub struct Permissions {
	inner: CorePermissions,
}

#[wasm_bindgen]
impl Permissions {
	/// Build from snake_case base flag names (e.g. `"access"`, `"owner"`,
	/// `"admin"`) and external bit `offsets`.
	#[wasm_bindgen(constructor)]
	pub fn new(flags: Vec<String>, offsets: Vec<u8>) -> JsResult<Permissions> {
		let flags = flags
			.iter()
			.map(|flag| parse_base_flag(flag))
			.collect::<JsResult<Vec<_>>>()?;
		let inner = CorePermissions::from_flags(&flags, &offsets)
			.map_err(|error| coded_error("INVALID_PERMISSIONS", &error.to_string()))?;
		Ok(Self { inner })
	}
}

impl Permissions {
	pub(crate) fn to_core(&self) -> CorePermissions {
		self.inner.clone()
	}
}

/// A MODIFY_PERMISSIONS change: who, how, and what. Build with `forAccount` or
/// `forCertificate`, then optionally attach permissions and a target.
#[wasm_bindgen]
pub struct PermissionChange {
	inner: ModifyPermissions,
}

#[wasm_bindgen]
impl PermissionChange {
	/// Change permissions for an account `principal`. `method` is `"add"`,
	/// `"subtract"`, or `"set"`.
	#[wasm_bindgen(js_name = forAccount)]
	pub fn for_account(principal: &Account, method: String) -> JsResult<PermissionChange> {
		Ok(Self {
			inner: ModifyPermissions {
				principal: ModifyPermissionsPrincipal::Account(principal.inner()),
				method: parse_adjust_method(&method)?,
				permissions: None,
				target: None,
			},
		})
	}

	/// Change the default permissions tied to a certificate, identified by its
	/// 32-byte hex `hash` and issuing `account`.
	#[wasm_bindgen(js_name = forCertificate)]
	pub fn for_certificate(hash: String, account: &Account, method: String) -> JsResult<PermissionChange> {
		Ok(Self {
			inner: ModifyPermissions {
				principal: ModifyPermissionsPrincipal::Certificate {
					hash: parse_hash32(&hash, "certificate hash")?,
					account: account.inner(),
				},
				method: parse_adjust_method(&method)?,
				permissions: None,
				target: None,
			},
		})
	}

	/// Attach the permissions to apply. Omit to clear (requires `"set"`).
	#[wasm_bindgen(js_name = setPermissions)]
	pub fn set_permissions(&mut self, permissions: &Permissions) {
		self.inner.permissions = Some(permissions.to_core());
	}

	/// Scope the change to a `target` account.
	#[wasm_bindgen(js_name = setTarget)]
	pub fn set_target(&mut self, target: &Account) {
		self.inner.target = Some(target.inner());
	}
}

impl PermissionChange {
	pub(crate) fn to_core(&self) -> ModifyPermissions {
		self.inner.clone()
	}
}
