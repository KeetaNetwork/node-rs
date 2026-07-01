//! Byte-conformance tests for generated ISO 20022 sequence-of-choice types.
//! Requires the `rasn` feature.
#![cfg(feature = "rasn")]

use keetanetwork_asn1::generated::iso20022::{
	OrganizationIdentification, OrganizationIdentificationChoice, PersonIdentification, PersonIdentificationChoice,
};
use keetanetwork_asn1::{decode, encode};

// SEQUENCE OF { [0] EXPLICIT UTF8String "A", [0] EXPLICIT UTF8String "B" }
//   30 0a
//     a0 03  0c 01 41   -- [0] EXPLICIT UTF8String "A"
//     a0 03  0c 01 42   -- [0] EXPLICIT UTF8String "B"
const ORG_ID_TWO_BIC_VECTOR: &str = "300aa0030c0141a0030c0142";

#[test]
fn test_organization_identification_encodes_as_sequence_of_choice() {
	let value = OrganizationIdentification(vec![
		OrganizationIdentificationChoice::bic("A".into()),
		OrganizationIdentificationChoice::bic("B".into()),
	]);

	let der = encode(&value).expect("encode OrganizationIdentification");
	assert_eq!(hex::encode(der), ORG_ID_TWO_BIC_VECTOR, "sequence-of-choice DER bytes");
}

#[test]
fn test_person_identification_round_trips_repeated_alternatives() {
	let value = PersonIdentification(vec![
		PersonIdentificationChoice::other(vec![]),
		PersonIdentificationChoice::other(vec![]),
	]);

	let der = encode(&value).expect("encode PersonIdentification");
	let decoded: PersonIdentification = decode(&der).expect("decode PersonIdentification");
	assert_eq!(decoded, value, "sequence-of-choice round-trips a repeated alternative");
}
