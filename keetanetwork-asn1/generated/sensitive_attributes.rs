#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
use rasn::prelude::*;
#[doc = " Inner type "]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SensitiveAttributeCipher {
	pub algorithm: ObjectIdentifier,
	#[rasn(identifier = "ivOrNonce")]
	pub iv_or_nonce: OctetString,
	pub key: OctetString,
}
impl SensitiveAttributeCipher {
	pub fn new(algorithm: ObjectIdentifier, iv_or_nonce: OctetString, key: OctetString) -> Self {
		Self { algorithm, iv_or_nonce, key }
	}
}
#[doc = " Inner type "]
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SensitiveAttributeHashedValue {
	#[rasn(identifier = "encryptedSalt")]
	pub encrypted_salt: OctetString,
	pub algorithm: ObjectIdentifier,
	pub value: OctetString,
}
impl SensitiveAttributeHashedValue {
	pub fn new(encrypted_salt: OctetString, algorithm: ObjectIdentifier, value: OctetString) -> Self {
		Self { encrypted_salt, algorithm, value }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SensitiveAttribute {
	pub version: Integer,
	pub cipher: SensitiveAttributeCipher,
	#[rasn(identifier = "hashedValue")]
	pub hashed_value: SensitiveAttributeHashedValue,
	#[rasn(identifier = "encryptedValue")]
	pub encrypted_value: OctetString,
}
impl SensitiveAttribute {
	pub fn new(
		version: Integer,
		cipher: SensitiveAttributeCipher,
		hashed_value: SensitiveAttributeHashedValue,
		encrypted_value: OctetString,
	) -> Self {
		Self { version, cipher, hashed_value, encrypted_value }
	}
}
