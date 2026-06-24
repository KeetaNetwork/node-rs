//! P2P message JSON codec

use serde_json::{Map, Value};
use snafu::Snafu;

/// Reserved keys that are not the message *type*.
const ID_KEY: &str = "id";
const TTL_KEY: &str = "ttl";

/// A decoded P2P message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2PMessage {
	/// Unique message identifier, used for de-duplication.
	pub id: String,
	/// The message type (the single non-reserved key).
	pub kind: String,
	/// The payload carried under `kind`.
	pub data: Value,
	/// Remaining time-to-live (forwarding hops), if present.
	pub ttl: Option<u32>,
}

/// Failure modes of [`P2PMessage::parse`].
#[derive(Debug, Snafu)]
pub enum MessageError {
	/// The frame was not valid JSON.
	#[snafu(display("message is not valid json"))]
	Json {
		/// Underlying parse error.
		source: serde_json::Error,
	},
	/// The frame was valid JSON but not an object.
	#[snafu(display("message is not a json object"))]
	NotObject,
	/// The frame had no string `id`.
	#[snafu(display("message is missing a string id"))]
	MissingId,
	/// The frame carried no type key (only reserved keys).
	#[snafu(display("message is missing a type"))]
	MissingType,
	/// The frame carried more than one type key.
	#[snafu(display("message has more than one type"))]
	AmbiguousType,
}

impl P2PMessage {
	/// Parse a frame, rejecting anything that is not a well-formed message.
	///
	/// # Errors
	///
	/// Returns a [`MessageError`] when the frame is not a JSON object with a
	/// string `id` and exactly one non-reserved type key.
	pub fn parse(text: &str) -> Result<Self, MessageError> {
		let value: Value = serde_json::from_str(text).map_err(|source| MessageError::Json { source })?;
		let Value::Object(object) = value else {
			return Err(MessageError::NotObject);
		};

		let id = object
			.get(ID_KEY)
			.and_then(Value::as_str)
			.ok_or(MessageError::MissingId)?
			.to_owned();

		let ttl = object.get(TTL_KEY).and_then(Value::as_u64).map(|ttl| ttl as u32);

		let is_reserved = |key: &str| key == ID_KEY || key == TTL_KEY;
		let mut types = object.iter().filter(|(key, _)| !is_reserved(key));

		let (kind, data) = types.next().ok_or(MessageError::MissingType)?;
		if types.next().is_some() {
			return Err(MessageError::AmbiguousType);
		}

		Ok(Self { id, kind: kind.clone(), data: data.clone(), ttl })
	}

	/// Encode this message to its JSON form.
	pub fn encode(&self) -> String {
		let mut object = Map::new();
		object.insert(ID_KEY.to_owned(), Value::from(self.id.clone()));
		object.insert(self.kind.clone(), self.data.clone());

		if let Some(ttl) = self.ttl {
			object.insert(TTL_KEY.to_owned(), Value::from(ttl));
		}

		Value::Object(object).to_string()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_extracts_id_type_and_ttl() {
		let message = P2PMessage::parse(r#"{"id":"m1","greeting":{"kind":0},"ttl":8}"#)
			.expect("a well-formed message must parse");
		assert_eq!(message.id, "m1", "id must be extracted");
		assert_eq!(message.kind, "greeting", "the non-reserved key must be the type");
		assert_eq!(message.ttl, Some(8), "ttl must be extracted");
	}

	#[test]
	fn parse_allows_absent_ttl() {
		let message = P2PMessage::parse(r#"{"id":"m1","add":"hash"}"#).expect("ttl is optional");
		assert_eq!(message.ttl, None, "absent ttl must be None");
	}

	#[test]
	fn parse_rejects_missing_id() {
		assert!(matches!(P2PMessage::parse(r#"{"add":"x"}"#), Err(MessageError::MissingId)));
	}

	#[test]
	fn parse_rejects_missing_type() {
		assert!(matches!(P2PMessage::parse(r#"{"id":"m1"}"#), Err(MessageError::MissingType)));
	}

	#[test]
	fn parse_rejects_ambiguous_type() {
		assert!(matches!(P2PMessage::parse(r#"{"id":"m1","a":1,"b":2}"#), Err(MessageError::AmbiguousType)));
	}

	#[test]
	fn parse_rejects_non_object() {
		assert!(matches!(P2PMessage::parse("42"), Err(MessageError::NotObject)));
	}

	#[test]
	fn round_trips_through_parse() {
		let message = P2PMessage {
			id: "m1".to_owned(),
			kind: "test".to_owned(),
			data: Value::from("payload"),
			ttl: Some(4),
		};
		let parsed = P2PMessage::parse(&message.encode()).expect("serialized message must re-parse");
		assert_eq!(parsed, message, "encoded message must round-trip");
	}
}
