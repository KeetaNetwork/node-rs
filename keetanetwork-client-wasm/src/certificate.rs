//! JS `CertificateChange`: input for MANAGE_CERTIFICATE (add or remove).

use alloc::string::String;
use alloc::vec::Vec;

use keetanetwork_block::{
	AdjustMethod, CertificateDer, CertificateOrHash, IntermediateCertificates, ManageCertificate,
};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::convert::{coded_error, parse_hash32, JsResult};

/// A MANAGE_CERTIFICATE change. Build with `add` (then optional intermediates)
/// or `remove`.
#[wasm_bindgen]
pub struct CertificateChange {
	inner: ManageCertificate,
}

#[wasm_bindgen]
impl CertificateChange {
	/// Add the X.509 `certificate` given as hex DER bytes.
	pub fn add(certificate: String) -> JsResult<CertificateChange> {
		Ok(Self {
			inner: ManageCertificate {
				method: AdjustMethod::Add,
				certificate_or_hash: CertificateOrHash::Certificate(decode_der(&certificate)?),
				intermediate_certificates: Some(IntermediateCertificates::Bundle(Vec::new())),
			},
		})
	}

	/// Append an intermediate `certificate` (hex DER) to an `add` change.
	#[wasm_bindgen(js_name = addIntermediate)]
	pub fn add_intermediate(&mut self, certificate: String) -> JsResult<()> {
		let der = decode_der(&certificate)?;
		match &mut self.inner.intermediate_certificates {
			Some(IntermediateCertificates::Bundle(bundle)) => {
				bundle.push(der);
				Ok(())
			}
			_ => Err(coded_error("INVALID_CERTIFICATE", "intermediates apply only to an add")),
		}
	}

	/// Remove the certificate identified by its 32-byte hex `hash`.
	pub fn remove(hash: String) -> JsResult<CertificateChange> {
		Ok(Self {
			inner: ManageCertificate {
				method: AdjustMethod::Subtract,
				certificate_or_hash: CertificateOrHash::Hash(parse_hash32(&hash, "certificate hash")?),
				intermediate_certificates: None,
			},
		})
	}
}

impl CertificateChange {
	pub(crate) fn to_core(&self) -> ManageCertificate {
		self.inner.clone()
	}
}

fn decode_der(certificate: &str) -> JsResult<CertificateDer> {
	hex::decode(certificate)
		.map(CertificateDer::from)
		.map_err(|_| coded_error("INVALID_CERTIFICATE", "certificate must be hex DER"))
}
