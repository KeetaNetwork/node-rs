//! Schema-driven positional ASN.1 DER codec.
//!
//! A declarative [`Schema`] drives structural encoding and decoding of a DER
//! value, byte-compatible with the reference TypeScript `ValidateASN1`.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use rasn::types::ObjectIdentifier;
use snafu::Snafu;

use crate::Asn1Time;

/// A declarative ASN.1 schema node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Schema {
	/// A `UTF8String` leaf.
	Utf8,
	/// An `OBJECT IDENTIFIER` leaf.
	Oid,
	/// An `OCTET STRING` leaf.
	OctetString,
	/// A date leaf (`GeneralizedTime`, or a legacy `UTCTime` on decode).
	Date,
	/// An `[value] EXPLICIT` context wrapper around an inner schema.
	Context(u8, Box<Schema>),
	/// An optional member.
	Optional(Box<Schema>),
	/// A `CHOICE`; the first alternative that matches is used.
	Choice(Vec<Schema>),
	/// A `SEQUENCE OF` a single inner schema.
	SequenceOf(Box<Schema>),
	/// A `SEQUENCE` struct with named, ordered members.
	Struct(Vec<Field>),
}

/// A named member of a [`Schema::Struct`], in positional schema order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
	/// The member's name.
	pub name: &'static str,
	/// The member's schema.
	pub schema: Schema,
}

impl Field {
	/// Construct a struct field.
	pub fn new(name: &'static str, schema: Schema) -> Self {
		Self { name, schema }
	}
}

/// The decoded ASN.1 intermediate value, produced by [`der_decode`] and
/// consumed by [`der_encode`]. Structs and `SEQUENCE OF` share [`Asn1::Seq`];
/// the schema disambiguates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1 {
	/// A `SEQUENCE` (or `SEQUENCE OF`) of components.
	Seq(Vec<Asn1>),
	/// An explicit context tag `[value]` wrapping one inner value.
	Context(u8, Box<Asn1>),
	/// A string leaf. Legacy `PrintableString`/`IA5String` inputs decode here
	/// and re-encode canonically as `UTF8String`, the same normalization
	/// [`Asn1::Date`] applies to legacy `UTCTime`.
	Str(String),
	/// An `OBJECT IDENTIFIER` leaf in dotted-decimal form.
	Oid(String),
	/// An `OCTET STRING` leaf.
	Octets(Vec<u8>),
	/// A date leaf.
	Date(Asn1Time),
}

/// A schema-driven DER codec failure.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
pub enum SchemaCodecError {
	/// The DER input ended mid-element.
	#[snafu(display("truncated DER element"))]
	Truncated,
	/// Bytes remained after a single top-level DER element.
	#[snafu(display("trailing bytes after DER element"))]
	Trailing,
	/// A DER length used the indefinite form or an unrepresentable width.
	#[snafu(display("malformed DER length"))]
	MalformedLength,
	/// A universal tag the codec does not model.
	#[snafu(display("unsupported ASN.1 tag {tag:#x}"))]
	UnsupportedTag {
		/// The offending identifier octet.
		tag: u8,
	},
	/// A context tag number exceeded the single-octet form.
	#[snafu(display("context tag number {tag} too large"))]
	ContextTagTooLarge {
		/// The offending context tag number.
		tag: u8,
	},
	/// An explicit context tag wrapped more than one element.
	#[snafu(display("explicit context tag wraps multiple elements"))]
	MultipleContextElements,
	/// A value did not match its schema.
	#[snafu(display("value does not match its schema"))]
	SchemaMismatch,
	/// A `SEQUENCE` had too few or too many components for its schema.
	#[snafu(display("component count outside schema bounds"))]
	ComponentCountOutOfBounds,
	/// An `OBJECT IDENTIFIER` value could not be parsed or serialized.
	#[snafu(display("invalid object identifier"))]
	InvalidOid,
	/// A date value could not be parsed or serialized.
	#[snafu(display("invalid date/time value"))]
	InvalidDateTime,
}

// -- Schema helpers ---------------------------------------------------------

/// Whether a schema node is an optional member.
pub fn is_optional(schema: &Schema) -> bool {
	matches!(schema, Schema::Optional(_))
}

/// The inner schema of an optional member, or the schema itself when required.
fn optional_inner(schema: &Schema) -> &Schema {
	match schema {
		Schema::Optional(inner) => inner,
		other => other,
	}
}

/// Produce the backwards-compatible schema by stripping one context-tag layer
/// from each struct member.
pub fn unwrap_context_tags(schema: &Schema) -> Schema {
	let Schema::Struct(fields) = schema else {
		return schema.clone();
	};

	let unwrapped = fields
		.iter()
		.map(|field| {
			let stripped = unwrap_field(&field.schema);
			Field::new(field.name, stripped)
		})
		.collect();
	Schema::Struct(unwrapped)
}

/// Strip a context tag from a struct member, preserving an optional wrapper.
fn unwrap_field(field_schema: &Schema) -> Schema {
	match field_schema {
		Schema::Optional(inner) => {
			let stripped = unwrap_single(inner);
			Schema::Optional(Box::new(stripped))
		}
		other => unwrap_single(other),
	}
}

/// Strip a single explicit context layer, returning its inner schema.
fn unwrap_single(schema: &Schema) -> Schema {
	match schema {
		Schema::Context(_, inner) => (**inner).clone(),
		other => other.clone(),
	}
}

// -- Structural matching ----------------------------------------------------

/// Whether an [`Asn1`] value structurally satisfies a [`Schema`]. This is the
/// backtracking predicate used by [`match_tuple`]; it holds exactly when the
/// caller could project `value` through `schema` without a structural error.
pub(crate) fn matches(value: &Asn1, schema: &Schema) -> bool {
	match schema {
		Schema::Optional(inner) => matches(value, inner),
		Schema::Context(tag, inner) => matches_context(value, *tag, inner),
		Schema::Choice(alternatives) => alternatives
			.iter()
			.any(|alternative| matches(value, alternative)),
		Schema::SequenceOf(inner) => matches_sequence_of(value, inner),
		Schema::Struct(fields) => matches_struct(value, fields),
		Schema::Utf8 => matches!(value, Asn1::Str(_)),
		Schema::Oid => matches!(value, Asn1::Oid(_)),
		Schema::OctetString => matches!(value, Asn1::Octets(_)),
		Schema::Date => matches!(value, Asn1::Date(_)),
	}
}

/// Whether `value` is an explicit `[tag]` wrapping a value matching `inner`.
fn matches_context(value: &Asn1, tag: u8, inner: &Schema) -> bool {
	match value {
		Asn1::Context(actual, contains) if *actual == tag => matches(contains, inner),
		_ => false,
	}
}

/// Whether every component of a `SEQUENCE OF` matches the inner schema.
fn matches_sequence_of(value: &Asn1, inner: &Schema) -> bool {
	match value {
		Asn1::Seq(items) => items.iter().all(|item| matches(item, inner)),
		_ => false,
	}
}

/// Whether a `SEQUENCE` positionally satisfies a struct's member schemas.
fn matches_struct(value: &Asn1, fields: &[Field]) -> bool {
	let Asn1::Seq(components) = value else {
		return false;
	};

	let schemas: Vec<&Schema> = fields.iter().map(|field| &field.schema).collect();
	match_tuple(components, &schemas).is_ok()
}

/// Match a sequence of components against an ordered list of member schemas,
/// backtracking over optional members, returning each member's matched
/// component (or `None` when absent).
pub fn match_tuple<'a>(components: &'a [Asn1], schemas: &[&Schema]) -> Result<Vec<Option<&'a Asn1>>, SchemaCodecError> {
	let required = schemas.iter().filter(|schema| !is_optional(schema)).count();
	if components.len() < required || components.len() > schemas.len() {
		return Err(SchemaCodecError::ComponentCountOutOfBounds);
	}

	let mut out: Vec<Option<&Asn1>> = Vec::new();
	let mut index = 0;
	while index < schemas.len() {
		let schema = schemas[index];

		// An optional member that is neither last nor past the input can collide
		// with the following member, so it needs backtracking resolution.
		let is_ambiguous_optional = is_optional(schema) && index < schemas.len() - 1 && index < components.len();
		if is_ambiguous_optional {
			out.extend(resolve_ambiguous_optional(components, schemas, index)?);
			break;
		}

		let component = components.get(index);
		out.push(against_one(component, schema)?);
		index += 1;
	}

	while matches!(out.last(), Some(None)) {
		out.pop();
	}

	Ok(out)
}

/// Resolve an optional member whose tag can collide with the following member:
/// try consuming the current component as this member, else treat it as absent
/// and match the remainder. Returns the matched components from `index` onward.
fn resolve_ambiguous_optional<'a>(
	components: &'a [Asn1],
	schemas: &[&Schema],
	index: usize,
) -> Result<Vec<Option<&'a Asn1>>, SchemaCodecError> {
	let remaining = &schemas[index + 1..];
	let head = &components[index..];

	let mut present = vec![optional_inner(schemas[index])];
	present.extend_from_slice(remaining);
	if let Ok(matched) = match_tuple(head, &present) {
		return Ok(matched);
	}

	let mut out = vec![None];
	out.extend(match_tuple(head, remaining)?);
	Ok(out)
}

/// Match a single component against a member schema, yielding `None` for an
/// absent optional member and erroring for an absent or mismatched required
/// member.
fn against_one<'a>(component: Option<&'a Asn1>, schema: &Schema) -> Result<Option<&'a Asn1>, SchemaCodecError> {
	match component {
		None if is_optional(schema) => Ok(None),
		None => Err(SchemaCodecError::SchemaMismatch),
		Some(value) if matches(value, schema) => Ok(Some(value)),
		Some(_) => Err(SchemaCodecError::SchemaMismatch),
	}
}

// -- DER: Asn1 <-> bytes ----------------------------------------------------

/// Serialize an [`Asn1`] intermediate value to DER bytes.
pub fn der_encode(value: &Asn1) -> Result<Vec<u8>, SchemaCodecError> {
	match value {
		Asn1::Seq(items) => {
			let mut body = Vec::new();
			for item in items {
				let encoded = der_encode(item)?;
				body.extend_from_slice(&encoded);
			}
			Ok(wrap(0x30, &body))
		}
		Asn1::Context(tag, contains) => {
			if *tag > 30 {
				return Err(SchemaCodecError::ContextTagTooLarge { tag: *tag });
			}
			let body = der_encode(contains)?;
			Ok(wrap(0xa0 | tag, &body))
		}
		Asn1::Str(text) => Ok(wrap(0x0c, text.as_bytes())),
		Asn1::Oid(oid) => {
			let parsed = parse_dotted_oid(oid)?;
			let der = rasn::der::encode(&parsed).map_err(|_| SchemaCodecError::InvalidOid)?;
			Ok(der)
		}
		Asn1::Octets(bytes) => Ok(wrap(0x04, bytes)),
		Asn1::Date(time) => {
			let der = rasn::der::encode(time).map_err(|_| SchemaCodecError::InvalidDateTime)?;
			Ok(der)
		}
	}
}

/// Parse a dotted-decimal string into a rasn `ObjectIdentifier`.
fn parse_dotted_oid(dotted: &str) -> Result<ObjectIdentifier, SchemaCodecError> {
	let arcs: Result<Vec<u32>, _> = dotted.split('.').map(|arc| arc.parse::<u32>()).collect();
	let arcs = arcs.map_err(|_| SchemaCodecError::InvalidOid)?;
	ObjectIdentifier::new(arcs).ok_or(SchemaCodecError::InvalidOid)
}

/// Wrap a body in a tag and DER length prefix.
fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(body.len() + 6);
	out.push(tag);
	let length = der_length(body.len());
	out.extend_from_slice(&length);
	out.extend_from_slice(body);
	out
}

/// Encode a DER definite length.
fn der_length(length: usize) -> Vec<u8> {
	if length < 0x80 {
		return vec![length as u8];
	}

	let mut bytes = Vec::new();
	let mut remaining = length;
	while remaining > 0 {
		bytes.push((remaining & 0xff) as u8);
		remaining >>= 8;
	}
	bytes.reverse();

	let mut out = Vec::with_capacity(bytes.len() + 1);
	out.push(0x80 | bytes.len() as u8);
	out.extend_from_slice(&bytes);
	out
}

/// Parse a single DER element into the [`Asn1`] intermediate value.
pub fn der_decode(der: &[u8]) -> Result<Asn1, SchemaCodecError> {
	let tlv = read_tlv(der)?;
	if !tlv.rest.is_empty() {
		return Err(SchemaCodecError::Trailing);
	}

	decode_tlv(tlv.tag, tlv.value, tlv.raw)
}

/// Interpret a parsed tag/value into the [`Asn1`] intermediate value.
fn decode_tlv(tag: u8, value: &[u8], raw: &[u8]) -> Result<Asn1, SchemaCodecError> {
	// Context class (bits 8-7 == 10): an explicit tag wrapping one inner element.
	if tag & 0xc0 == 0x80 {
		let inner = read_tlv(value)?;
		if !inner.rest.is_empty() {
			return Err(SchemaCodecError::MultipleContextElements);
		}
		let contains = decode_tlv(inner.tag, inner.value, inner.raw)?;
		return Ok(Asn1::Context(tag & 0x1f, Box::new(contains)));
	}

	match tag {
		0x30 => {
			let components = decode_components(value)?;
			Ok(Asn1::Seq(components))
		}
		0x0c | 0x13 | 0x16 => {
			let text = core::str::from_utf8(value).map_err(|_| SchemaCodecError::SchemaMismatch)?;
			Ok(Asn1::Str(text.to_string()))
		}
		0x06 => {
			let oid: ObjectIdentifier = rasn::der::decode(raw).map_err(|_| SchemaCodecError::InvalidOid)?;
			Ok(Asn1::Oid(oid.to_string()))
		}
		0x04 => Ok(Asn1::Octets(value.to_vec())),
		0x17 | 0x18 => {
			let time: Asn1Time = rasn::der::decode(raw).map_err(|_| SchemaCodecError::InvalidDateTime)?;
			Ok(Asn1::Date(time))
		}
		_ => Err(SchemaCodecError::UnsupportedTag { tag }),
	}
}

/// Split a constructed body into its component values.
fn decode_components(body: &[u8]) -> Result<Vec<Asn1>, SchemaCodecError> {
	let mut out = Vec::new();
	let mut rest = body;
	while !rest.is_empty() {
		let tlv = read_tlv(rest)?;
		let component = decode_tlv(tlv.tag, tlv.value, tlv.raw)?;
		out.push(component);
		rest = tlv.rest;
	}

	Ok(out)
}

/// A parsed DER tag-length-value element and the bytes trailing it.
struct Tlv<'a> {
	/// The identifier octet (tag).
	tag: u8,
	/// The element's content (value) bytes.
	value: &'a [u8],
	/// The whole element (tag, length, and value), for re-decoding a leaf.
	raw: &'a [u8],
	/// The bytes following this element.
	rest: &'a [u8],
}

/// Read one short/long-form DER TLV element from the front of `input`.
fn read_tlv(input: &[u8]) -> Result<Tlv<'_>, SchemaCodecError> {
	let tag = *input.first().ok_or(SchemaCodecError::Truncated)?;
	let first_len = usize::from(*input.get(1).ok_or(SchemaCodecError::Truncated)?);

	let (length, header) = if first_len < 0x80 {
		(first_len, 2)
	} else {
		// Reject the indefinite-length form (invalid for DER) and any width that
		// cannot fit a usize, then accumulate with checked arithmetic so untrusted
		// input cannot overflow into a wrapped, attacker-chosen length.
		let count = first_len & 0x7f;
		if count == 0 || count > core::mem::size_of::<usize>() {
			return Err(SchemaCodecError::MalformedLength);
		}

		let bytes = input.get(2..2 + count).ok_or(SchemaCodecError::Truncated)?;
		let length = bytes
			.iter()
			.try_fold(0usize, |acc, byte| acc.checked_mul(256)?.checked_add(usize::from(*byte)))
			.ok_or(SchemaCodecError::MalformedLength)?;

		(length, 2 + count)
	};

	let end = header
		.checked_add(length)
		.ok_or(SchemaCodecError::MalformedLength)?;
	let value = input.get(header..end).ok_or(SchemaCodecError::Truncated)?;
	let raw = input.get(..end).ok_or(SchemaCodecError::Truncated)?;
	let rest = &input[end..];

	Ok(Tlv { tag, value, raw, rest })
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::{TimeZone, Utc};

	fn from_hex(hex: &str) -> Vec<u8> {
		(0..hex.len())
			.step_by(2)
			.map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex byte"))
			.collect()
	}

	fn utc(year: i32, month: u32, day: u32) -> Asn1Time {
		let instant = Utc
			.with_ymd_and_hms(year, month, day, 0, 0, 0)
			.single()
			.expect("valid instant");
		Asn1Time::new(instant)
	}

	#[test]
	fn round_trips_intermediate_values() -> Result<(), SchemaCodecError> {
		let cases = vec![
			// Bare SEQUENCE { UTF8String, OBJECT IDENTIFIER }.
			Asn1::Seq(vec![Asn1::Str("hello".to_string()), Asn1::Oid("1.3.101.112".to_string())]),
			// Explicit context wrapping an OCTET STRING.
			Asn1::Seq(vec![Asn1::Context(3, Box::new(Asn1::Octets(vec![1, 2, 3])))]),
			// Bare leaves.
			Asn1::Str("x".to_string()),
			Asn1::Date(utc(1990, 1, 1)),
			// A 200-byte payload forces the long-form DER length.
			Asn1::Seq(vec![Asn1::Str("a".repeat(200))]),
		];

		for value in &cases {
			let der = der_encode(value)?;
			assert_eq!(&der_decode(&der)?, value);
		}
		Ok(())
	}

	#[test]
	fn der_encode_rejects_oversized_context_tag() {
		let value = Asn1::Context(31, Box::new(Asn1::Str("x".to_string())));
		assert_eq!(der_encode(&value), Err(SchemaCodecError::ContextTagTooLarge { tag: 31 }));
	}

	#[test]
	fn der_encode_rejects_malformed_oid() {
		assert_eq!(der_encode(&Asn1::Oid("not-an-oid".to_string())), Err(SchemaCodecError::InvalidOid));
	}

	#[test]
	fn der_decode_rejects_unsupported_tag() {
		// INTEGER (0x02) is not modelled by the codec.
		assert_eq!(der_decode(&from_hex("020101")), Err(SchemaCodecError::UnsupportedTag { tag: 0x02 }));
	}

	#[test]
	fn der_decode_rejects_multi_element_context() {
		// [0] EXPLICIT wrapping two UTF8Strings is invalid.
		assert_eq!(der_decode(&from_hex("a0060c01410c0142")), Err(SchemaCodecError::MultipleContextElements));
	}

	#[test]
	fn match_tuple_rejects_component_count_out_of_bounds() {
		let schemas: Vec<Schema> = vec![Schema::Utf8];
		let refs: Vec<&Schema> = schemas.iter().collect();
		let components = vec![Asn1::Str("a".to_string()), Asn1::Str("b".to_string())];
		assert_eq!(match_tuple(&components, &refs), Err(SchemaCodecError::ComponentCountOutOfBounds));
	}

	#[test]
	fn matches_a_sequence_of_leaf() {
		let schema = Schema::SequenceOf(Box::new(Schema::Utf8));
		let value = Asn1::Seq(vec![Asn1::Str("a".to_string()), Asn1::Str("b".to_string())]);
		assert!(matches(&value, &schema));
	}

	#[test]
	fn unwrap_context_tags_strips_one_explicit_layer() {
		let schema = Schema::Struct(vec![
			Field::new("id", Schema::Context(0, Box::new(Schema::Utf8))),
			Field::new("issuer", Schema::Optional(Box::new(Schema::Context(1, Box::new(Schema::Utf8))))),
		]);
		let expected = Schema::Struct(vec![
			Field::new("id", Schema::Utf8),
			Field::new("issuer", Schema::Optional(Box::new(Schema::Utf8))),
		]);
		assert_eq!(unwrap_context_tags(&schema), expected);
	}

	#[test]
	fn matches_a_bare_choice_by_alternative_tag() {
		// A bare CHOICE {[0] Utf8, [1] Utf8} matches either alternative's own tag.
		let schema = Schema::Choice(vec![
			Schema::Context(0, Box::new(Schema::Utf8)),
			Schema::Context(1, Box::new(Schema::Utf8)),
		]);

		let code = Asn1::Context(0, Box::new(Asn1::Str("HOME".to_string())));
		let proprietary = Asn1::Context(1, Box::new(Asn1::Str("OTHER".to_string())));
		assert!(matches(&code, &schema));
		assert!(matches(&proprietary, &schema));
	}

	#[test]
	fn match_tuple_backtracks_over_a_colliding_optional() -> Result<(), SchemaCodecError> {
		// [id [0], issuer [1] OPTIONAL, schemeName bare CHOICE {code [0]}]: the
		// bare schemeName [0] collides with id [0]; with issuer absent the
		// matcher must still bind both components positionally.
		let schemas: Vec<Schema> = vec![
			Schema::Context(0, Box::new(Schema::Utf8)),
			Schema::Optional(Box::new(Schema::Context(1, Box::new(Schema::Utf8)))),
			Schema::Choice(vec![Schema::Context(0, Box::new(Schema::Utf8))]),
		];
		let refs: Vec<&Schema> = schemas.iter().collect();
		let components = vec![
			Asn1::Context(0, Box::new(Asn1::Str("123".to_string()))),
			Asn1::Context(0, Box::new(Asn1::Str("SSN".to_string()))),
		];

		let matched = match_tuple(&components, &refs)?;
		assert_eq!(matched.len(), 3);
		assert!(matched[0].is_some());
		assert!(matched[1].is_none());
		assert!(matched[2].is_some());
		Ok(())
	}

	#[test]
	fn decodes_legacy_utc_time() -> Result<(), SchemaCodecError> {
		// UTCTime "900101000000Z" (tag 0x17) decodes to the same instant a
		// GeneralizedTime would.
		let decoded = der_decode(&from_hex("170d3930303130313030303030305a"))?;
		assert_eq!(decoded, Asn1::Date(utc(1990, 1, 1)));
		Ok(())
	}

	#[test]
	fn der_decode_rejects_indefinite_length() {
		assert_eq!(der_decode(&[0x30, 0x80]), Err(SchemaCodecError::MalformedLength));
	}

	#[test]
	fn der_decode_rejects_trailing_bytes() {
		let mut der = der_encode(&Asn1::Str("x".to_string())).expect("encode");
		der.push(0x00);
		assert_eq!(der_decode(&der), Err(SchemaCodecError::Trailing));
	}
}
