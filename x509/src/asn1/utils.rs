//! Utilities for working with ASN.1 types

#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
use crate::asn1::ObjectIdentifier;
#[cfg(feature = "serde")]
use crate::asn1::OctetString;

/// Serialize an ObjectIdentifier
#[cfg(feature = "serde")]
pub fn serialize_oid<S>(oid: &ObjectIdentifier, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&oid.to_string())
}

/// Deserialize an ObjectIdentifier
#[cfg(feature = "serde")]
pub fn deserialize_oid<'de, D>(deserializer: D) -> Result<ObjectIdentifier, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	ObjectIdentifier::new(&s).map_err(serde::de::Error::custom)
}

/// Serialize an OctetString
#[cfg(feature = "serde")]
pub fn serialize_octet_string<S>(octet_string: &OctetString, serializer: S) -> Result<S::Ok, S::Error>
where
	S: serde::Serializer,
{
	serializer.serialize_str(&hex::encode(octet_string.as_bytes()))
}

/// Deserialize an OctetString
#[cfg(feature = "serde")]
pub fn deserialize_octet_string<'de, D>(deserializer: D) -> Result<OctetString, D::Error>
where
	D: serde::Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
	OctetString::new(&*bytes).map_err(serde::de::Error::custom)
}
