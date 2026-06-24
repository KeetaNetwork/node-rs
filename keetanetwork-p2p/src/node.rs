//! The switch's callback boundary to the node it serves.
//!
//! The [`P2PSwitch`](crate::switch::P2PSwitch) handles transport, de-dupe, and
//! peer learning, then hands every accepted message to a [`NodeLike`].

use async_trait::async_trait;

use crate::connection::P2PConnection;
use crate::message::P2PMessage;

/// The node-side recipient of messages the switch accepts from peers.
#[async_trait]
pub trait NodeLike: Send + Sync {
	/// Handle a de-duplicated, parsed message that arrived on `connection`.
	async fn recv_message_from_peer(&self, connection: &dyn P2PConnection, message: &P2PMessage);
}
