//! Peer identity types and their JSON encoding.
//!
//! A peer is either a *participant* (an anonymous listener, e.g. a wallet) or a
//! *representative* advertising signed p2p/api endpoints.

use core::str::FromStr;

use serde_json::{Map, Value};

/// The role a peer plays on the network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
	/// An anonymous listener (wallet/client).
	Participant,
	/// A representative advertising endpoints.
	Representative,
}

impl NodeKind {
	/// The encoded discriminant.
	pub fn discriminant(self) -> u8 {
		match self {
			NodeKind::Participant => 0,
			NodeKind::Representative => 1,
		}
	}

	/// The kind for an encoded discriminant, if recognized.
	pub fn from_discriminant(value: u64) -> Option<Self> {
		match value {
			0 => Some(NodeKind::Participant),
			1 => Some(NodeKind::Representative),
			_ => None,
		}
	}
}

/// How a representative prefers to receive ledger updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdatePref {
	/// Poll/POST over HTTP.
	Http,
	/// Stream over a WebSocket.
	Websocket,
}

impl UpdatePref {
	/// The encoded string.
	pub fn as_str(self) -> &'static str {
		match self {
			UpdatePref::Http => "http",
			UpdatePref::Websocket => "websocket",
		}
	}
}

/// The string did not name a known [`UpdatePref`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownUpdatePref;

impl FromStr for UpdatePref {
	type Err = UnknownUpdatePref;

	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value {
			"http" => Ok(UpdatePref::Http),
			"websocket" => Ok(UpdatePref::Websocket),
			_ => Err(UnknownUpdatePref),
		}
	}
}

/// A representative's advertised endpoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepEndpoints {
	/// WebSocket p2p endpoint.
	pub p2p: String,
	/// HTTP api endpoint.
	pub api: String,
}

/// A known peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P2PPeer {
	/// An anonymous listener.
	Participant,
	/// A representative and its advertised, signed endpoints.
	Representative {
		/// Public-key string identifying the representative account.
		key: String,
		/// Advertised endpoints.
		endpoints: RepEndpoints,
		/// Update delivery preference.
		prefer_updates: UpdatePref,
		/// Base64-encoded signature over the advertised endpoints, when the
		/// peer authenticated via signature.
		signature: Option<String>,
	},
}

impl P2PPeer {
	/// This peer's role.
	pub fn kind(&self) -> NodeKind {
		match self {
			P2PPeer::Participant => NodeKind::Participant,
			P2PPeer::Representative { .. } => NodeKind::Representative,
		}
	}

	/// A stable identifier used to key peer registries. Representatives are
	/// keyed by account and p2p endpoint; participants share one id.
	pub fn id(&self) -> String {
		match self {
			P2PPeer::Participant => "participant".to_owned(),
			P2PPeer::Representative { key, endpoints, .. } => {
				let mut id = String::with_capacity(key.len() + endpoints.p2p.len() + 5);
				id.push_str("rep_");
				id.push_str(key);
				id.push('@');
				id.push_str(&endpoints.p2p);
				id
			}
		}
	}

	/// Decode a peer from its JSON object, returning `None` when the structure
	/// is invalid. Does not verify signatures.
	pub fn from_json(value: &Value) -> Option<Self> {
		let object = value.as_object()?;
		let kind = NodeKind::from_discriminant(object.get("kind")?.as_u64()?)?;
		match kind {
			NodeKind::Participant => Some(P2PPeer::Participant),
			NodeKind::Representative => {
				let endpoints = object.get("endpoints")?.as_object()?;
				let p2p = endpoints.get("p2p")?.as_str()?.to_owned();
				let api = endpoints.get("api")?.as_str()?.to_owned();
				let prefer_updates = object.get("preferUpdates")?.as_str()?.parse().ok()?;
				let key = object.get("key")?.as_str()?.to_owned();
				let signature = object.get("signature").and_then(Value::as_str).map(str::to_owned);
				Some(P2PPeer::Representative { key, endpoints: RepEndpoints { p2p, api }, prefer_updates, signature })
			}
		}
	}

	/// Encode this peer to its JSON object.
	pub fn to_json(&self) -> Value {
		let mut object = Map::new();
		object.insert("kind".to_owned(), Value::from(self.kind().discriminant()));
		if let P2PPeer::Representative { key, endpoints, prefer_updates, signature } = self {
			let mut endpoint_object = Map::new();
			endpoint_object.insert("p2p".to_owned(), Value::from(endpoints.p2p.clone()));
			endpoint_object.insert("api".to_owned(), Value::from(endpoints.api.clone()));
			object.insert("endpoints".to_owned(), Value::Object(endpoint_object));
			object.insert("preferUpdates".to_owned(), Value::from(prefer_updates.as_str()));
			object.insert("key".to_owned(), Value::from(key.clone()));
			if let Some(signature) = signature {
				object.insert("signature".to_owned(), Value::from(signature.clone()));
			}
		}
		Value::Object(object)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn participant_round_trips() {
		let peer = P2PPeer::Participant;
		let decoded = P2PPeer::from_json(&peer.to_json()).expect("participant must decode");
		assert_eq!(decoded, peer, "participant must round-trip through json");
	}

	#[test]
	fn representative_round_trips() {
		let peer = P2PPeer::Representative {
			key: "keeta_pub".to_owned(),
			endpoints: RepEndpoints { p2p: "ws://h/p2p".to_owned(), api: "http://h/api".to_owned() },
			prefer_updates: UpdatePref::Websocket,
			signature: Some("c2ln".to_owned()),
		};
		let decoded = P2PPeer::from_json(&peer.to_json()).expect("representative must decode");
		assert_eq!(decoded, peer, "representative must round-trip through json");
	}

	#[test]
	fn from_json_rejects_unknown_kind() {
		let value = serde_json::json!({ "kind": 9 });
		assert!(P2PPeer::from_json(&value).is_none(), "unknown kind must be rejected");
	}

	#[test]
	fn from_json_rejects_representative_without_endpoints() {
		let value = serde_json::json!({ "kind": 1, "key": "k", "preferUpdates": "http" });
		assert!(P2PPeer::from_json(&value).is_none(), "missing endpoints must be rejected");
	}

	#[test]
	fn representative_id_includes_key_and_endpoint() {
		let peer = P2PPeer::Representative {
			key: "k".to_owned(),
			endpoints: RepEndpoints { p2p: "ws://h/p2p".to_owned(), api: "http://h/api".to_owned() },
			prefer_updates: UpdatePref::Http,
			signature: None,
		};
		assert_eq!(peer.id(), "rep_k@ws://h/p2p", "rep id must combine key and p2p endpoint");
	}
}
