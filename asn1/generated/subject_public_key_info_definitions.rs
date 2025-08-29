#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::all)]
use super::algorithm_identifier_definitions::AlgorithmIdentifier;
use rasn::prelude::*;
#[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SubjectPublicKeyInfo {
	pub algorithm: AlgorithmIdentifier,
	#[rasn(identifier = "subjectPublicKey")]
	pub subject_public_key: BitString,
}
impl SubjectPublicKeyInfo {
}
