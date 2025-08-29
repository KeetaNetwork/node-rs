#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
use rasn::prelude::*;
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier {
	pub algorithm: ObjectIdentifier,
	pub parameters: Option<Any>,
}
impl AlgorithmIdentifier {}
