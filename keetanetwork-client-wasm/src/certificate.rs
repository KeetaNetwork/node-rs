//! JS `ManageCertificate`: input for a MANAGE_CERTIFICATE operation (add or
//! remove).

use alloc::string::String;
use alloc::vec::Vec;

use keetanetwork_block::{
	AdjustMethod, CertificateDer, CertificateOrHash, IntermediateCertificates,
	ManageCertificate as CoreManageCertificate,
};
use keetanetwork_x509::certificates::CertificateHash;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::convert::{coded_error, JsResult};

/// A certificate hash is the lowercase hex of its 32-byte SHA3-256 digest.
#[wasm_bindgen(typescript_custom_section)]
const CERTIFICATE_HASH_TS: &str = "export type CertificateHash = string;";

/// A MANAGE_CERTIFICATE operation. Build with `add` (then optional
/// intermediates) or `remove`.
#[wasm_bindgen]
pub struct ManageCertificate {
	inner: CoreManageCertificate,
}

#[wasm_bindgen]
impl ManageCertificate {
	/// Add the X.509 `certificate` given as hex DER bytes.
	pub fn add(certificate: String) -> JsResult<ManageCertificate> {
		Ok(Self {
			inner: CoreManageCertificate {
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

	/// The certificate hash as a [`CertificateHash`] (hex), as used to look up
	/// or remove it. For an `add` this is `SHA3-256` of the certificate DER; for
	/// a `remove` it is the supplied hash.
	#[wasm_bindgen(getter)]
	pub fn hash(&self) -> String {
		hex::encode(self.inner.certificate_or_hash.hash())
	}

	/// Remove the certificate identified by its 32-byte hex `hash`.
	pub fn remove(hash: String) -> JsResult<ManageCertificate> {
		let parsed: CertificateHash = hash
			.parse()
			.map_err(|_| coded_error("INVALID_CERTIFICATE_HASH", "certificate hash must be hex"))?;
		let digest: [u8; 32] = parsed
			.as_ref()
			.try_into()
			.map_err(|_| coded_error("INVALID_CERTIFICATE_HASH", "certificate hash must be 32 bytes"))?;
		Ok(Self {
			inner: CoreManageCertificate {
				method: AdjustMethod::Subtract,
				certificate_or_hash: CertificateOrHash::Hash(digest),
				intermediate_certificates: None,
			},
		})
	}
}

impl ManageCertificate {
	pub(crate) fn to_core(&self) -> CoreManageCertificate {
		self.inner.clone()
	}
}

fn decode_der(certificate: &str) -> JsResult<CertificateDer> {
	hex::decode(certificate)
		.map(CertificateDer::from)
		.map_err(|_| coded_error("INVALID_CERTIFICATE", "certificate must be hex DER"))
}
