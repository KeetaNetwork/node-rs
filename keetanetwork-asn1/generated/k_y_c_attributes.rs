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
#[rasn(choice)]
pub enum AttributeValue {
	#[rasn(tag(context, 0))]
	plainValue(OctetString),
	#[rasn(tag(context, 1))]
	sensitiveValue(OctetString),
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct Attribute {
	pub name: ObjectIdentifier,
	pub value: AttributeValue,
}
impl Attribute {
	pub fn new(name: ObjectIdentifier, value: AttributeValue) -> Self {
		Self { name, value }
	}
}
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct KYCAttributes(pub SequenceOf<Attribute>);
