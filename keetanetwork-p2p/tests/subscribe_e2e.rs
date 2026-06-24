//! End-to-end test of the client account-change subscription over a real
//! WebSocket, driven through the p2p `TokioWsConnector`.
//! 
//! TODO: Remove stub transport and use a real transport when the ledger
//! and node are implemented.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use keetanetwork_block::testing::generate_ed25519_ref;
use keetanetwork_block::{Amount, Block};
use keetanetwork_client::{
	AccountState, Acl, Certificate, ChainPage, ChainQuery, ClientConfig, ClientError, HistoryEntry, HistoryQuery,
	KeetaClient, LedgerChecksum, LedgerSide, NodeTransport, RepPart, Representative, Runtime, TokenBalance,
	TokioRuntime, TransportFactory, UserClient, UserEvent, Vote, VoteQuote, VoteStaple, WsConnector,
};
use keetanetwork_p2p::backends::TokioWsConnector;
use num_bigint::BigInt;
use tokio::net::TcpListener;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// A transport factory whose every representative serves one fixed account
/// state. Only [`NodeTransport::account_state`] is exercised by the
/// subscription; the remaining methods are unreachable in this test.
#[derive(Debug)]
struct StubFactory {
	state: AccountState,
}

impl TransportFactory for StubFactory {
	fn create(&self, _url: &str) -> Arc<dyn NodeTransport> {
		Arc::new(StubTransport { state: self.state.clone() })
	}
}

#[derive(Debug)]
struct StubTransport {
	state: AccountState,
}

#[async_trait]
impl NodeTransport for StubTransport {
	async fn account_state(&self, _account: &str) -> Result<AccountState, ClientError> {
		Ok(self.state.clone())
	}

	async fn node_version(&self) -> Result<String, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn balance(&self, _account: &str, _token: &str) -> Result<Amount, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn balances(&self, _account: &str) -> Result<Vec<TokenBalance>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn account_states(&self, _accounts: &str) -> Result<Vec<AccountState>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn head_block(&self, _account: &str) -> Result<Option<Block>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn account_head_info(&self, _account: &str) -> Result<Option<(Block, Amount)>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn pending_block(&self, _account: &str) -> Result<Option<Block>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn block(&self, _hash: &str, _side: Option<LedgerSide>) -> Result<Option<Block>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn successor_block(&self, _hash: &str) -> Result<Option<Block>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn block_by_idempotent(&self, _account: &str, _key: &str) -> Result<Option<Block>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn block_votes(&self, _hash: &str, _side: LedgerSide) -> Result<Option<Vec<Vote>>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn chain_page(&self, _account: &str, _query: &ChainQuery) -> Result<ChainPage, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn history_page(&self, _account: &str, _query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn global_history_page(&self, _query: &HistoryQuery) -> Result<Vec<HistoryEntry>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn vote_staples_after(&self, _start: &str, _limit: Option<i64>) -> Result<Vec<VoteStaple>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn node_representative(&self) -> Result<Representative, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn representative(&self, _rep: &str) -> Result<Representative, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn representatives(&self) -> Result<Vec<Representative>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn ledger_checksum(&self) -> Result<LedgerChecksum, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn acls_by_principal(&self, _account: &str) -> Result<Vec<Acl>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn acls_by_entity(&self, _account: &str) -> Result<Vec<Acl>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn certificates(&self, _account: &str) -> Result<Vec<Certificate>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn certificate(&self, _account: &str, _hash: &str) -> Result<Option<Certificate>, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn create_vote(
		&self,
		_blocks: &[Block],
		_prior: &[Vote],
		_quote: Option<&VoteQuote>,
	) -> Result<Vote, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn create_vote_quote(&self, _blocks: &[Block]) -> Result<VoteQuote, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn publish_staple(&self, _staple: &VoteStaple) -> Result<bool, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn acls_by_principal_with_info(&self, _account: &str) -> Result<serde_json::Value, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn node_stats(&self) -> Result<serde_json::Value, ClientError> {
		Err(ClientError::NoRepresentatives)
	}

	async fn node_peers(&self) -> Result<serde_json::Value, ClientError> {
		Err(ClientError::NoRepresentatives)
	}
}

/// Accept one connection, wait for the participant greeting, then echo a
/// greeting and push a single `add` notification.
async fn serve_one_add(listener: TcpListener) {
	let Ok((stream, _)) = listener.accept().await else {
		return;
	};
	let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
		return;
	};

	// The client's first frame is its participant greeting.
	let _greeting = socket.next().await;

	let echo = serde_json::json!({ "id": "srv-greet", "greeting": { "kind": 0 } }).to_string();
	let _ = socket.send(Message::text(echo)).await;

	let notification = serde_json::json!({ "id": "srv-add", "add": "head-hash" }).to_string();
	let _ = socket.send(Message::text(notification)).await;

	// Hold the socket open so the client can finish processing before close.
	tokio::time::sleep(Duration::from_secs(3)).await;
}

#[tokio::test]
async fn subscription_emits_change_on_socket_add_notification() {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("server must bind");
	let address = listener.local_addr().expect("server must expose its address");
	tokio::spawn(serve_one_add(listener));

	let state = AccountState {
		representative: Some("rep".to_owned()),
		head: Some("head-hash".to_owned()),
		height: None,
		info: None,
		supply: None,
		balances: Vec::new(),
	};
	let factory: Arc<dyn TransportFactory> = Arc::new(StubFactory { state });
	let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
	let rep = RepPart { key: "rep".to_owned(), url: "http://stub".to_owned(), weight: BigInt::from(1u8) };
	let client = KeetaClient::with_parts([rep], factory, runtime, ClientConfig::default(), true);

	let account = generate_ed25519_ref(1);
	let connector: Arc<dyn WsConnector> = Arc::new(TokioWsConnector);
	let user = UserClient::from_parts(client, None)
		.with_account(Arc::clone(&account))
		.with_subscription(connector, format!("ws://{address}"))
		.expect("subscription must configure");

	let (sender, mut receiver) = unbounded_channel();
	let id = user
		.on(UserEvent::Change, move |_state| {
			let _ = sender.send(());
		})
		.expect("change listener must register");

	let fired = timeout(Duration::from_secs(5), receiver.recv()).await;
	assert!(fired.is_ok(), "the change handler must fire before the timeout");
	assert!(fired.expect("recv must resolve").is_some(), "the change handler must deliver an event");

	user.off(id);
}
