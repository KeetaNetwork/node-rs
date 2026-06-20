//! Serde JSON encoding functionality for x509 certificates.

pub(crate) use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub(crate) use serde_json::Value;

use core::str::FromStr;

use chrono::{DateTime, Utc};
use der::asn1::{ObjectIdentifier, OctetString};
use serde::ser::SerializeStruct;

use crate::certificates::{Certificate, CertificateBundle, CertificateHash, CertificateOptions, Extension};
use crate::utils::{dn_to_name_value_pairs, time_to_utc};

/// Name-value pair for Distinguished Names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameValuePair {
	pub name: String,
	pub value: String,
}

impl Serialize for Certificate {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use serde::ser::Error;

		let hash =
			CertificateHash::try_from(self).map_err(|_| S::Error::custom("Failed to compute certificate hash"))?;
		let hash_hex = hex::encode(hash.as_ref());

		let extensions: Vec<Extension> = self
			.tbs_certificate
			.extensions
			.as_ref()
			.map(|exts| {
				exts.iter()
					.map(|ext| Extension {
						extn_id: ext.extn_id,
						critical: ext.critical,
						extn_value: ext.extn_value.clone(),
					})
					.collect()
			})
			.unwrap_or_default();

		// Convert serial number bytes to hex string
		let serial_bytes = self.tbs_certificate.serial_number.as_bytes();
		let serial_hex = hex::encode(serial_bytes);

		// Convert Time to DateTime<Utc> for RFC3339 formatting
		let not_before_dt: DateTime<Utc> = time_to_utc(self.tbs_certificate.validity.not_before);
		let not_after_dt: DateTime<Utc> = time_to_utc(self.tbs_certificate.validity.not_after);

		let mut state = serializer.serialize_struct("Certificate", 14)?;
		state.serialize_field("serial", &serial_hex)?;
		state.serialize_field("subject", &self.to_subject())?;
		state.serialize_field("issuer", &self.to_issuer())?;
		state.serialize_field("subject_dn", &dn_to_name_value_pairs(&self.tbs_certificate.subject))?;
		state.serialize_field("issuer_dn", &dn_to_name_value_pairs(&self.tbs_certificate.issuer))?;
		state.serialize_field("not_before", &not_before_dt.to_rfc3339())?;
		state.serialize_field("not_after", &not_after_dt.to_rfc3339())?;
		state.serialize_field("is_ca", &self.is_ca())?;
		state.serialize_field("is_self_signed", &self.is_self_signed())?;
		state.serialize_field("hash", &hash_hex)?;
		state.serialize_field("hash_field", &hash_hex)?;
		state.serialize_field("base_extensions", &self.parse_base_extensions())?;
		state.serialize_field(
			"pem",
			&self
				.to_pem()
				.map_err(|_| S::Error::custom("Failed to convert to PEM"))?,
		)?;
		state.serialize_field("extensions", &extensions)?;

		state.end()
	}
}

impl<'de> Deserialize<'de> for Certificate {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use serde::de::Error;

		let value: Value = Value::deserialize(deserializer)?;
		let obj = value
			.as_object()
			.ok_or_else(|| D::Error::custom("Expected object"))?;

		// Extract PEM field and parse the certificate
		let pem = obj
			.get("pem")
			.and_then(|v| v.as_str())
			.ok_or_else(|| D::Error::custom("Missing or invalid pem field"))?;

		// Parse the certificate from PEM
		let cert = Certificate::from_str(pem).map_err(|_| D::Error::custom("Failed to parse certificate from PEM"))?;

		Ok(cert)
	}
}

impl Serialize for CertificateBundle {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let mut state = serializer.serialize_struct("CertificateBundle", 4)?;
		state.serialize_field("certificate", &self.certificate)?;
		state.serialize_field("options", &self.options)?;

		// Convert the certificate set to Vec for serialization
		let root_certs: Vec<&Certificate> = self.root.iter().collect();
		let intermediate_certs: Vec<&Certificate> = self.intermediate.iter().collect();

		state.serialize_field("root", &root_certs)?;
		state.serialize_field("intermediate", &intermediate_certs)?;

		state.end()
	}
}

impl<'de> Deserialize<'de> for CertificateBundle {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		use alloc::collections::BTreeSet;

		use serde::de::Error;

		let value: Value = Value::deserialize(deserializer)?;
		let obj = value
			.as_object()
			.ok_or_else(|| D::Error::custom("Expected object"))?;

		// Extract certificate
		let certificate: Certificate = serde_json::from_value(
			obj.get("certificate")
				.ok_or_else(|| D::Error::custom("Missing certificate field"))?
				.clone(),
		)
		.map_err(|e| D::Error::custom(format!("Failed to deserialize certificate: {e}")))?;

		// Extract options
		let options: CertificateOptions = serde_json::from_value(
			obj.get("options")
				.ok_or_else(|| D::Error::custom("Missing options field"))?
				.clone(),
		)
		.map_err(|e| D::Error::custom(format!("Failed to deserialize options: {e}")))?;

		// Extract root certificates
		let root_vec: Vec<Certificate> = serde_json::from_value(
			obj.get("root")
				.ok_or_else(|| D::Error::custom("Missing root field"))?
				.clone(),
		)
		.map_err(|e| D::Error::custom(format!("Failed to deserialize root certificates: {e}")))?;
		let root: BTreeSet<Certificate> = root_vec.into_iter().collect();

		// Extract intermediate certificates
		let intermediate_vec: Vec<Certificate> = serde_json::from_value(
			obj.get("intermediate")
				.ok_or_else(|| D::Error::custom("Missing intermediate field"))?
				.clone(),
		)
		.map_err(|e| D::Error::custom(format!("Failed to deserialize intermediate certificates: {e}")))?;
		let intermediate: BTreeSet<Certificate> = intermediate_vec.into_iter().collect();

		Ok(CertificateBundle { certificate, options, root, intermediate })
	}
}

/// Serialize an ObjectIdentifier
pub fn serialize_oid<S>(oid: &ObjectIdentifier, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&oid.to_string())
}

/// Deserialize an ObjectIdentifier
pub fn deserialize_oid<'de, D>(deserializer: D) -> Result<ObjectIdentifier, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let name = String::deserialize(deserializer)?;
	ObjectIdentifier::new(&name).map_err(serde::de::Error::custom)
}

/// Serialize an OctetString
pub fn serialize_octet_string<S>(octet_string: &OctetString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&hex::encode(octet_string.as_bytes()))
}

/// Deserialize an OctetString
pub fn deserialize_octet_string<'de, D>(deserializer: D) -> Result<OctetString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
	OctetString::new(&*bytes).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::CERTIFICATE_TEST_SETS;

	type TestResult = Result<(), Box<dyn std::error::Error>>;

	#[test]
	fn test_certificate_serialize() -> TestResult {
		for test_set in CERTIFICATE_TEST_SETS.iter() {
			let cert = Certificate::from_str(test_set.chain.root)?;
			let json_result = serde_json::to_string_pretty(&cert);
			assert!(json_result.is_ok(), "Failed to serialize {} certificate", test_set.algorithm);

			let json_str = json_result?;
			assert!(json_str.contains("serial"));
			assert!(json_str.contains("subject"));
			assert!(json_str.contains("issuer"));
			assert!(json_str.contains("pem"));
		}

		Ok(())
	}

	#[test]
	fn test_certificate_roundtrip() -> TestResult {
		for test_set in CERTIFICATE_TEST_SETS.iter() {
			let original_cert = Certificate::from_str(test_set.chain.root)?;

			// Serialize and deserialize
			let json_str = serde_json::to_string(&original_cert)?;
			// Verify they are equivalent
			let deserialized_cert: Certificate = serde_json::from_str(&json_str)?;
			assert_eq!(original_cert, deserialized_cert, "Roundtrip failed for {} certificate", test_set.algorithm);
		}

		Ok(())
	}

	#[test]
	fn test_certificate_json_fields() -> TestResult {
		let cert = Certificate::from_str(CERTIFICATE_TEST_SETS[0].chain.root)?;
		let json_value: serde_json::Value = serde_json::to_value(&cert)?;

		// Verify all expected fields are present
		let obj = json_value.as_object().ok_or("not an object")?;
		assert!(obj.contains_key("serial"));
		assert!(obj.contains_key("subject"));
		assert!(obj.contains_key("issuer"));
		assert!(obj.contains_key("subject_dn"));
		assert!(obj.contains_key("issuer_dn"));
		assert!(obj.contains_key("not_before"));
		assert!(obj.contains_key("not_after"));
		assert!(obj.contains_key("is_ca"));
		assert!(obj.contains_key("is_self_signed"));
		assert!(obj.contains_key("hash"));
		assert!(obj.contains_key("hash_field"));
		assert!(obj.contains_key("base_extensions"));
		assert!(obj.contains_key("pem"));
		assert!(obj.contains_key("extensions"));

		Ok(())
	}

	#[test]
	fn test_certificate_bundle_serialize() -> TestResult {
		let cert = Certificate::from_str(CERTIFICATE_TEST_SETS[0].chain.root)?;
		let bundle = CertificateBundle::try_from(cert)?;

		let json_result = serde_json::to_string_pretty(&bundle);
		assert!(json_result.is_ok(), "Failed to serialize certificate bundle");

		let json_str = json_result?;
		assert!(json_str.contains("certificate"));
		assert!(json_str.contains("options"));
		assert!(json_str.contains("root"));
		assert!(json_str.contains("intermediate"));

		Ok(())
	}

	#[test]
	fn test_certificate_bundle_roundtrip() -> TestResult {
		let cert = Certificate::from_str(CERTIFICATE_TEST_SETS[0].chain.root)?;
		let original_bundle = CertificateBundle::try_from(cert)?;

		// Serialize and deserialize
		let json_str = serde_json::to_string(&original_bundle)?;
		let deserialized_bundle: CertificateBundle = serde_json::from_str(&json_str)?;
		assert_eq!(original_bundle.certificate, deserialized_bundle.certificate);
		assert_eq!(original_bundle.options, deserialized_bundle.options);
		assert_eq!(original_bundle.root, deserialized_bundle.root);
		assert_eq!(original_bundle.intermediate, deserialized_bundle.intermediate);

		Ok(())
	}

	#[test]
	fn test_name_value_pair_serde() {
		let name = "commonName".to_string();
		let value = "Test Certificate".to_string();

		let pair = NameValuePair { name, value };
		assert_eq!(pair.name, "commonName");
		assert_eq!(pair.value, "Test Certificate");

		let cloned = pair.clone();
		assert_eq!(pair.name, cloned.name);
		assert_eq!(pair.value, cloned.value);

		let debug_str = format!("{pair:?}");
		assert!(debug_str.contains("NameValuePair"));
		assert!(debug_str.contains("commonName"));
		assert!(debug_str.contains("Test Certificate"));
	}
}
