//! WASI Preview 2 component exposing the networked KeetaNet client.

use core::cell::RefCell;
use core::future::Future;
use core::str::FromStr;
use std::sync::Arc;

use keetanetwork_account::KeyPairType;
use keetanetwork_bindings::client::ledger_side;
use keetanetwork_bindings::parse::{amount as parse_amount, amount_to_string};
use keetanetwork_block::{
	AccountRef, AdjustMethod, BlockBuilder, BlockHash, CertificateDer, CertificateOrHash, IdentifierCreateArguments,
	IntermediateCertificates, ManageCertificate, ModifyPermissions, ModifyPermissionsPrincipal,
	MultisigCreateArguments, SetInfo,
};
use keetanetwork_client::{
	AcceptSwapRequest, AccountInfo as CoreInfo, AccountState as CoreState, Acl as CoreAcl,
	Certificate as CoreCertificate, ChainQuery, ClientConfig, ClientError, CreateSwapRequest,
	HistoryEntry as CoreHistory, HistoryQuery, KeetaClient, LedgerChecksum as CoreChecksum, RepPart,
	Representative as CoreRep, SwapExpectation, SwapTokenAmount, TransactionBuilder, TransmitOptions, UserClient,
	WasiRuntime, WasiTransportFactory,
};
use num_bigint::BigInt;
use wstd::runtime::block_on;

use crate::pure;

wit_bindgen::generate!({
	world: "keeta-client",
	path: "wit",
});

use exports::keeta::client::node::{
	AccountInfo, AccountState, Acl, AdjustMethod as WitAdjustMethod, BlockBuilder as BlockBuilderResource, Certificate,
	ChainPage, ChainQuery as WitChainQuery, CodedError, Guest, GuestBlockBuilder, GuestClient, GuestTransaction,
	GuestUserClient, HeadInfo, HistoryEntry, HistoryQuery as WitHistoryQuery, LedgerChecksum, Representative,
	SignerSpec, SwapExpectation as WitSwapExpectation, SwapTokenAmount as WitSwapTokenAmount, TokenBalance,
	Transaction as TransactionResource, UserClient as UserClientResource,
};

/// Drive an async client call to completion on the `wstd` reactor, projecting
/// its error to the WIT boundary type.
fn run<T>(future: impl Future<Output = Result<T, ClientError>>) -> Result<T, CodedError> {
	block_on(future).map_err(CodedError::from)
}

/// Decode hex DER bytes, projecting a malformed input to the WIT boundary.
fn decode_der(value: &str) -> Result<Vec<u8>, CodedError> {
	hex::decode(value)
		.map_err(|_| CodedError { code: "INVALID_CERTIFICATE".into(), message: "certificate must be hex".into() })
}

/// Decode a 32-byte certificate hash from hex.
fn decode_hash(value: &str) -> Result<[u8; 32], CodedError> {
	let bytes = decode_der(value)
		.map_err(|_| CodedError { code: "INVALID_HASH".into(), message: "hash must be hex".into() })?;
	bytes
		.try_into()
		.map_err(|_| CodedError { code: "INVALID_HASH".into(), message: "hash must be 32 bytes".into() })
}

struct Component;

impl Guest for Component {
	type Client = NodeClient;
	type UserClient = AccountClient;
	type Transaction = TransactionState;
	type BlockBuilder = BuilderState;

	fn derive_identifier(
		spec: SignerSpec,
		kind: String,
		previous: Option<String>,
		op_index: u32,
	) -> Result<String, CodedError> {
		let account = account_from_spec(&spec)?;
		let kind = derivable_identifier_kind(&kind)?;
		let previous = previous.map(|hash| decode_hash(&hash)).transpose()?;
		let identifier = pure::generate_identifier(&account, kind, previous, op_index)?;
		Ok(pure::account_address(&identifier))
	}
}

/// Derive the signing account described by `spec`.
fn account_from_spec(spec: &SignerSpec) -> Result<AccountRef, CodedError> {
	Ok(pure::account_from_seed(&spec.seed, spec.index, &spec.algorithm)?)
}

/// Parse an identifier kind for local derivation. Unlike the shared parser
/// (which reserves multisig for the publishing path that supplies its create
/// arguments), local address derivation accepts every identifier type.
fn derivable_identifier_kind(kind: &str) -> Result<KeyPairType, CodedError> {
	match kind {
		"multisig" => Ok(KeyPairType::MULTISIG),
		other => Ok(keetanetwork_bindings::parse::identifier_type(other)?),
	}
}

/// A single-representative KeetaNet client backed by the WASI transport.
struct NodeClient {
	inner: KeetaClient,
}

impl From<ClientError> for CodedError {
	fn from(error: ClientError) -> Self {
		Self { code: error.code().into(), message: error.to_string() }
	}
}

impl From<keetanetwork_bindings::error::CodedError> for CodedError {
	fn from(error: keetanetwork_bindings::error::CodedError) -> Self {
		Self { code: error.code, message: error.message }
	}
}

impl From<keetanetwork_bindings::parse::ParseError> for CodedError {
	fn from(error: keetanetwork_bindings::parse::ParseError) -> Self {
		keetanetwork_bindings::error::CodedError::from(error).into()
	}
}

impl From<CoreRep> for Representative {
	fn from(rep: CoreRep) -> Self {
		Self { account: rep.account, weight: amount_to_string(rep.weight), api_url: rep.api_url }
	}
}

impl From<CoreInfo> for AccountInfo {
	fn from(info: CoreInfo) -> Self {
		Self { name: info.name, description: info.description, metadata: info.metadata }
	}
}

impl From<CoreState> for AccountState {
	fn from(state: CoreState) -> Self {
		Self {
			representative: state.representative,
			head: state.head,
			height: state.height.map(amount_to_string),
			info: state.info.map(AccountInfo::from),
			supply: state.supply.map(amount_to_string),
			balances: state
				.balances
				.into_iter()
				.map(|balance| TokenBalance { token: balance.token, amount: amount_to_string(balance.balance) })
				.collect(),
		}
	}
}

impl From<CoreChecksum> for LedgerChecksum {
	fn from(checksum: CoreChecksum) -> Self {
		Self {
			checksum: amount_to_string(checksum.checksum),
			moment: checksum.moment,
			moment_range: checksum.moment_range,
		}
	}
}

impl From<CoreHistory> for HistoryEntry {
	fn from(entry: CoreHistory) -> Self {
		Self { staple: pure::staple_to_hex(&entry.staple), id: entry.id, timestamp: entry.timestamp }
	}
}

impl From<WitChainQuery> for ChainQuery {
	fn from(query: WitChainQuery) -> Self {
		Self { start: query.start, end: query.end, limit: query.limit }
	}
}

impl From<WitHistoryQuery> for HistoryQuery {
	fn from(query: WitHistoryQuery) -> Self {
		Self { start: query.start, limit: query.limit }
	}
}

impl From<CoreAcl> for Acl {
	fn from(acl: CoreAcl) -> Self {
		Self { principal: acl.principal, entity: acl.entity, target: acl.target, permissions: acl.permissions }
	}
}

impl From<CoreCertificate> for Certificate {
	fn from(certificate: CoreCertificate) -> Self {
		Self { certificate: certificate.certificate, intermediates: certificate.intermediates }
	}
}

impl TryFrom<WitSwapTokenAmount> for SwapTokenAmount {
	type Error = CodedError;

	fn try_from(leg: WitSwapTokenAmount) -> Result<Self, Self::Error> {
		let token = leg
			.token
			.map(|token| pure::account_from_address(&token))
			.transpose()?;
		let amount = leg.amount.map(|amount| parse_amount(&amount)).transpose()?;
		Ok(Self { token, amount })
	}
}

impl TryFrom<WitSwapExpectation> for SwapExpectation {
	type Error = CodedError;

	fn try_from(expectation: WitSwapExpectation) -> Result<Self, Self::Error> {
		let receive = expectation
			.receive
			.map(SwapTokenAmount::try_from)
			.transpose()?;
		let send = expectation
			.send
			.map(SwapTokenAmount::try_from)
			.transpose()?;
		Ok(Self { receive, send })
	}
}

impl From<WitAdjustMethod> for AdjustMethod {
	fn from(method: WitAdjustMethod) -> Self {
		match method {
			WitAdjustMethod::Add => Self::Add,
			WitAdjustMethod::Subtract => Self::Subtract,
			WitAdjustMethod::Set => Self::Set,
		}
	}
}

/// An anonymous single-representative client keyed by its URL (no account).
fn single_rep_client(base_url: String) -> KeetaClient {
	let part = RepPart { key: base_url.clone(), url: base_url, weight: BigInt::from(1u8) };
	KeetaClient::with_parts(
		[part],
		Arc::new(WasiTransportFactory),
		Arc::new(WasiRuntime),
		ClientConfig::default(),
		true,
	)
}

impl GuestClient for NodeClient {
	fn new(base_url: String) -> Self {
		Self { inner: single_rep_client(base_url) }
	}

	fn node_version(&self) -> Result<String, CodedError> {
		run(self.inner.node_version())
	}

	fn account_balance(&self, account: String, token: String) -> Result<String, CodedError> {
		Ok(amount_to_string(run(self.inner.balance(account, token))?))
	}

	fn account_balances(&self, account: String) -> Result<Vec<TokenBalance>, CodedError> {
		Ok(run(self.inner.balances(account))?
			.into_iter()
			.map(|balance| TokenBalance { token: balance.token, amount: amount_to_string(balance.balance) })
			.collect())
	}

	fn token_supply(&self, token: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.token_supply(token))?.map(amount_to_string))
	}

	fn account_state(&self, account: String) -> Result<AccountState, CodedError> {
		Ok(AccountState::from(run(self.inner.state(account))?))
	}

	fn head_block(&self, account: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.head_block(account))?.map(|block| pure::block_to_hex(&block)))
	}

	fn block(&self, blockhash: String, side: Option<String>) -> Result<Option<String>, CodedError> {
		let side = ledger_side(side.as_deref())?;
		Ok(run(self.inner.block(blockhash, side))?.map(|block| pure::block_to_hex(&block)))
	}

	fn vote_staple(&self, blockhash: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.vote_staple(blockhash))?.map(|staple| pure::staple_to_hex(&staple)))
	}

	fn representative(&self, rep: String) -> Result<Representative, CodedError> {
		Ok(Representative::from(run(self.inner.representative(rep))?))
	}

	fn representatives(&self) -> Result<Vec<Representative>, CodedError> {
		Ok(run(self.inner.representatives())?
			.into_iter()
			.map(Representative::from)
			.collect())
	}

	fn ledger_checksum(&self) -> Result<LedgerChecksum, CodedError> {
		Ok(LedgerChecksum::from(run(self.inner.ledger_checksum())?))
	}

	fn chain(&self, account: String) -> Result<Vec<String>, CodedError> {
		Ok(run(self.inner.chain(account))?
			.iter()
			.map(pure::block_to_hex)
			.collect())
	}

	fn chain_page(&self, account: String, query: WitChainQuery) -> Result<ChainPage, CodedError> {
		let page = run(self
			.inner
			.chain_page_cursor(account, ChainQuery::from(query)))?;
		Ok(ChainPage { blocks: page.blocks.iter().map(pure::block_to_hex).collect(), next_key: page.next_key })
	}

	fn history(&self, account: String) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.history(account))?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn pending_block(&self, account: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.pending_block(account))?.map(|block| pure::block_to_hex(&block)))
	}

	fn account_head_info(&self, account: String) -> Result<Option<HeadInfo>, CodedError> {
		Ok(run(self.inner.account_head_info(account))?
			.map(|(block, height)| HeadInfo { block: pure::block_to_hex(&block), height: amount_to_string(height) }))
	}

	fn account_states(&self, accounts: Vec<String>) -> Result<Vec<AccountState>, CodedError> {
		let refs: Vec<&str> = accounts.iter().map(String::as_str).collect();
		Ok(run(self.inner.states(&refs))?
			.into_iter()
			.map(AccountState::from)
			.collect())
	}

	fn successor_block(&self, blockhash: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.successor_block(blockhash))?.map(|block| pure::block_to_hex(&block)))
	}

	fn block_by_idempotent(&self, account: String, key: String) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.block_by_idempotent(account, key))?.map(|block| pure::block_to_hex(&block)))
	}

	fn history_page(&self, account: String, query: WitHistoryQuery) -> Result<Vec<HistoryEntry>, CodedError> {
		let entries = run(self.inner.history_page(account, HistoryQuery::from(query)))?;
		Ok(entries.into_iter().map(HistoryEntry::from).collect())
	}

	fn node_representative(&self) -> Result<Representative, CodedError> {
		Ok(Representative::from(run(self.inner.node_representative())?))
	}

	fn acls_by_principal(&self, account: String) -> Result<Vec<Acl>, CodedError> {
		Ok(run(self.inner.acls_by_principal(account))?
			.into_iter()
			.map(Acl::from)
			.collect())
	}

	fn acls_by_entity(&self, account: String) -> Result<Vec<Acl>, CodedError> {
		Ok(run(self.inner.acls_by_entity(account))?
			.into_iter()
			.map(Acl::from)
			.collect())
	}

	fn certificates(&self, account: String) -> Result<Vec<Certificate>, CodedError> {
		Ok(run(self.inner.certificates(account))?
			.into_iter()
			.map(Certificate::from)
			.collect())
	}

	fn certificate(&self, account: String, hash: String) -> Result<Option<Certificate>, CodedError> {
		Ok(run(self.inner.certificate(account, hash))?.map(Certificate::from))
	}

	fn global_history(&self) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.global_history())?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn global_history_page(&self, query: WitHistoryQuery) -> Result<Vec<HistoryEntry>, CodedError> {
		let entries = run(self.inner.global_history_page(HistoryQuery::from(query)))?;
		Ok(entries.into_iter().map(HistoryEntry::from).collect())
	}

	fn vote_staples_after(&self, start: String) -> Result<Vec<String>, CodedError> {
		Ok(run(self.inner.vote_staples_after(start))?
			.iter()
			.map(pure::staple_to_hex)
			.collect())
	}

	fn vote_staples_after_page(&self, start: String, limit: Option<i64>) -> Result<Vec<String>, CodedError> {
		Ok(run(self.inner.vote_staples_after_page(start, limit))?
			.iter()
			.map(pure::staple_to_hex)
			.collect())
	}
}

/// A read-only [`UserClient`] scoped to one operating account.
struct AccountClient {
	inner: UserClient,
}

impl GuestUserClient for AccountClient {
	fn read_only(base_url: String, address: String) -> Result<UserClientResource, CodedError> {
		let account = pure::account_from_address(&address)?;
		let inner = UserClient::from_parts(single_rep_client(base_url), None).with_account(account);
		Ok(UserClientResource::new(Self { inner }))
	}

	fn with_signer(
		base_url: String,
		seed: String,
		index: u32,
		algorithm: String,
		network: String,
	) -> Result<UserClientResource, CodedError> {
		let signer = pure::account_from_seed(&seed, index, &algorithm)?;
		let network = BigInt::from_str(&network).map_err(|_| CodedError {
			code: "INVALID_INTEGER".into(),
			message: "network must be a decimal integer".into(),
		})?;
		let client = single_rep_client(base_url).with_network(network);

		let inner = UserClient::from_parts(client, Some(signer));
		Ok(UserClientResource::new(Self { inner }))
	}

	fn address(&self) -> Result<String, CodedError> {
		Ok(pure::account_address(&self.inner.account()?))
	}

	fn balance(&self, token: String) -> Result<String, CodedError> {
		Ok(amount_to_string(run(self.inner.balance(token))?))
	}

	fn all_balances(&self) -> Result<Vec<TokenBalance>, CodedError> {
		Ok(run(self.inner.all_balances())?
			.into_iter()
			.map(|balance| TokenBalance { token: balance.token, amount: amount_to_string(balance.balance) })
			.collect())
	}

	fn state(&self) -> Result<AccountState, CodedError> {
		Ok(AccountState::from(run(self.inner.state())?))
	}

	fn head(&self) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.head())?.map(|block| pure::block_to_hex(&block)))
	}

	fn chain(&self) -> Result<Vec<String>, CodedError> {
		Ok(run(self.inner.chain())?
			.iter()
			.map(pure::block_to_hex)
			.collect())
	}

	fn chain_page(&self, query: WitChainQuery) -> Result<Vec<String>, CodedError> {
		let blocks = run(self.inner.chain_page(ChainQuery::from(query)))?;
		Ok(blocks.iter().map(pure::block_to_hex).collect())
	}

	fn history(&self) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.history())?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn pending_block(&self) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.pending_block())?.map(|block| pure::block_to_hex(&block)))
	}

	fn send(&self, to: String, token: String, amount: String) -> Result<bool, CodedError> {
		let to = pure::account_from_address(&to)?;
		let token = pure::account_from_address(&token)?;
		let amount = parse_amount(&amount)?;
		run(self.inner.send(&to, &token, amount))
	}

	fn send_external(&self, to: String, token: String, amount: String, external: String) -> Result<bool, CodedError> {
		let to = pure::account_from_address(&to)?;
		let token = pure::account_from_address(&token)?;
		let amount = parse_amount(&amount)?;
		run(self.inner.send_external(&to, &token, amount, external))
	}

	fn set_rep(&self, rep: String) -> Result<bool, CodedError> {
		let rep = pure::account_from_address(&rep)?;
		run(self.inner.set_rep(&rep))
	}

	fn set_info(
		&self,
		name: Option<String>,
		description: Option<String>,
		metadata: Option<String>,
	) -> Result<bool, CodedError> {
		let info = SetInfo {
			name: name.unwrap_or_default(),
			description: description.unwrap_or_default(),
			metadata: metadata.unwrap_or_default(),
			default_permission: None,
		};
		run(self.inner.set_info(info))
	}

	fn modify_token(
		&self,
		token: String,
		holder: Option<String>,
		amount: String,
		method: WitAdjustMethod,
	) -> Result<bool, CodedError> {
		let token = pure::account_from_address(&token)?;
		let holder = holder
			.map(|holder| pure::account_from_address(&holder))
			.transpose()?;
		let amount = parse_amount(&amount)?;

		run(self
			.inner
			.modify_token_supply_and_balance(&token, holder.as_ref(), amount, AdjustMethod::from(method)))
	}

	fn update_permissions(
		&self,
		principal: String,
		method: WitAdjustMethod,
		permissions: Vec<String>,
		target: Option<String>,
	) -> Result<bool, CodedError> {
		let principal = ModifyPermissionsPrincipal::Account(pure::account_from_address(&principal)?);
		let permissions = match permissions.is_empty() {
			true => None,
			false => Some(pure::permissions_from_flags(&permissions, &[])?),
		};
		let target = target
			.map(|target| pure::account_from_address(&target))
			.transpose()?;
		let change = ModifyPermissions { principal, method: AdjustMethod::from(method), permissions, target };
		run(self.inner.update_permissions(change))
	}

	fn generate_multisig(&self, signers: Vec<String>, quorum: u32) -> Result<String, CodedError> {
		let signers = signers
			.iter()
			.map(|signer| pure::account_from_address(signer))
			.collect::<Result<Vec<_>, _>>()?;
		let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum: quorum.into() });
		let identifier = run(self
			.inner
			.generate_identifier(KeyPairType::MULTISIG, Some(arguments)))?;
		Ok(pure::account_address(&identifier))
	}

	fn generate_identifier(&self, kind: String) -> Result<String, CodedError> {
		let kind = keetanetwork_bindings::parse::identifier_type(&kind)?;
		let identifier = run(self.inner.generate_identifier(kind, None))?;
		Ok(pure::account_address(&identifier))
	}

	fn create_swap(
		&self,
		counterparty: String,
		send_token: String,
		send_amount: String,
		receive_token: String,
		receive_amount: String,
		receive_exact: bool,
	) -> Result<String, CodedError> {
		let request = CreateSwapRequest {
			counterparty: pure::account_from_address(&counterparty)?,
			send_token: pure::account_from_address(&send_token)?,
			send_amount: parse_amount(&send_amount)?,
			receive_token: pure::account_from_address(&receive_token)?,
			receive_amount: parse_amount(&receive_amount)?,
			receive_exact,
		};
		let block = run(self.inner.create_swap_request(request))?;
		Ok(pure::block_to_hex(&block))
	}

	fn accept_swap(&self, offer: String, expected: Option<WitSwapExpectation>) -> Result<Vec<String>, CodedError> {
		let block = pure::block_from_hex(&offer)?;
		let expected = expected.map(SwapExpectation::try_from).transpose()?;
		let blocks = run(self
			.inner
			.accept_swap_request(AcceptSwapRequest { block, expected }))?;
		Ok(blocks.iter().map(pure::block_to_hex).collect())
	}

	fn transmit(&self, blocks: Vec<String>) -> Result<bool, CodedError> {
		let blocks = blocks
			.iter()
			.map(|block| pure::block_from_hex(block))
			.collect::<Result<Vec<_>, _>>()?;
		run(self.inner.transmit(&blocks, TransmitOptions::default()))
	}

	fn add_certificate(&self, certificate: String, intermediates: Vec<String>) -> Result<bool, CodedError> {
		let certificate = CertificateDer::from(decode_der(&certificate)?);
		let intermediates = intermediates
			.iter()
			.map(|der| decode_der(der).map(CertificateDer::from))
			.collect::<Result<Vec<_>, _>>()?;
		let manage = ManageCertificate {
			method: AdjustMethod::Add,
			certificate_or_hash: CertificateOrHash::Certificate(certificate),
			intermediate_certificates: Some(IntermediateCertificates::Bundle(intermediates)),
		};
		run(self.inner.modify_certificate(manage))
	}

	fn remove_certificate(&self, hash: String) -> Result<bool, CodedError> {
		let manage = ManageCertificate {
			method: AdjustMethod::Subtract,
			certificate_or_hash: CertificateOrHash::Hash(decode_hash(&hash)?),
			intermediate_certificates: None,
		};
		run(self.inner.modify_certificate(manage))
	}

	fn begin(&self) -> Result<TransactionResource, CodedError> {
		let signer = self
			.inner
			.signer_account()
			.ok_or_else(|| CodedError { code: "SIGNER_REQUIRED".into(), message: "a signer is required".into() })?;
		let signer = Arc::clone(signer);
		let account = self.inner.account()?;
		let client = self.inner.client().clone();

		let mut builder = client.builder(&account);
		if account.to_string() != signer.to_string() {
			builder.for_account_with_signer(&account, &signer);
		}

		let state = TransactionState { builder: RefCell::new(builder), client, signer };
		Ok(TransactionResource::new(state))
	}
}

/// A staged, signer-bound transaction over a single operating account.
struct TransactionState {
	builder: RefCell<TransactionBuilder>,
	client: KeetaClient,
	signer: AccountRef,
}

impl GuestTransaction for TransactionState {
	fn send(&self, to: String, token: String, amount: String) -> Result<(), CodedError> {
		let to = pure::account_from_address(&to)?;
		let token = pure::account_from_address(&token)?;
		let amount = parse_amount(&amount)?;

		self.builder.borrow_mut().send(&to, &token, amount);

		Ok(())
	}

	fn send_external(&self, to: String, token: String, amount: String, external: String) -> Result<(), CodedError> {
		let to = pure::account_from_address(&to)?;
		let token = pure::account_from_address(&token)?;
		let amount = parse_amount(&amount)?;

		self.builder
			.borrow_mut()
			.send_external(&to, &token, amount, external);

		Ok(())
	}

	fn set_rep(&self, rep: String) -> Result<(), CodedError> {
		let rep = pure::account_from_address(&rep)?;

		self.builder.borrow_mut().set_rep(&rep);

		Ok(())
	}

	fn set_info(
		&self,
		name: Option<String>,
		description: Option<String>,
		metadata: Option<String>,
	) -> Result<(), CodedError> {
		let info = SetInfo {
			name: name.unwrap_or_default(),
			description: description.unwrap_or_default(),
			metadata: metadata.unwrap_or_default(),
			default_permission: None,
		};

		self.builder.borrow_mut().set_info(info);

		Ok(())
	}

	fn commit(&self) -> Result<Vec<String>, CodedError> {
		let blocks = run(self.builder.borrow_mut().build())?;
		let options = TransmitOptions { fee_signer: Some(Arc::clone(&self.signer)), ..Default::default() };

		let accepted = run(self.client.transmit(&blocks, options))?;
		if !accepted {
			return Err(CodedError { code: "TRANSMIT".into(), message: "the node rejected the transaction".into() });
		}

		Ok(blocks.iter().map(pure::block_to_hex).collect())
	}
}

/// A low-level, offline block assembler. `BlockBuilder` mutators consume `self`,
/// so the staged builder is held in an `Option` and threaded through each step;
/// `build-and-sign` takes it out and consumes it.
struct BuilderState {
	builder: RefCell<Option<BlockBuilder>>,
}

impl BuilderState {
	/// Apply `change` to the staged builder, threading ownership back in.
	fn stage(&self, change: impl FnOnce(BlockBuilder) -> BlockBuilder) -> Result<(), CodedError> {
		let mut slot = self.builder.borrow_mut();
		let builder = slot.take().ok_or_else(builder_consumed)?;
		*slot = Some(change(builder));
		Ok(())
	}
}

/// The builder has already produced its block and can no longer be mutated.
fn builder_consumed() -> CodedError {
	CodedError { code: "BUILDER_CONSUMED".into(), message: "the block has already been built".into() }
}

impl GuestBlockBuilder for BuilderState {
	fn new(network: u64, account: String) -> Result<BlockBuilderResource, CodedError> {
		let account = pure::account_from_address(&account)?;
		let builder = BlockBuilder::default()
			.with_network(network)
			.with_account(account);
		Ok(BlockBuilderResource::new(Self { builder: RefCell::new(Some(builder)) }))
	}

	fn version(&self, version: u32) -> Result<(), CodedError> {
		let version = pure::block_version(version)?;
		self.stage(|builder| builder.with_version(version))
	}

	fn previous(&self, previous: String) -> Result<(), CodedError> {
		let previous = BlockHash::from(decode_hash(&previous)?);
		self.stage(|builder| builder.with_previous(previous))
	}

	fn opening(&self) -> Result<(), CodedError> {
		self.stage(BlockBuilder::as_opening)
	}

	fn date(&self, unix_millis: i64) -> Result<(), CodedError> {
		let date = pure::block_time(unix_millis)?;
		self.stage(|builder| builder.with_date(date))
	}

	fn signer_single(&self, spec: SignerSpec) -> Result<(), CodedError> {
		let signer = pure::signer_single(account_from_spec(&spec)?);
		self.stage(|builder| builder.with_signer(signer))
	}

	fn signer_multisig(&self, multisig: String, members: Vec<SignerSpec>) -> Result<(), CodedError> {
		let multisig = pure::account_from_address(&multisig)?;
		let members = members
			.iter()
			.map(account_from_spec)
			.collect::<Result<Vec<_>, _>>()?;
		let signer = pure::signer_multisig(multisig, members);
		self.stage(|builder| builder.with_signer(signer))
	}

	fn op_create_multisig(&self, multisig: String, signers: Vec<String>, quorum: u32) -> Result<(), CodedError> {
		let multisig = pure::account_from_address(&multisig)?;
		let signers = signers
			.iter()
			.map(|signer| pure::account_from_address(signer))
			.collect::<Result<Vec<_>, _>>()?;
		let operation = pure::op_create_multisig(multisig, signers, quorum);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_modify_permissions(
		&self,
		principal: String,
		permissions: Vec<String>,
		method: WitAdjustMethod,
		target: Option<String>,
	) -> Result<(), CodedError> {
		let principal = pure::account_from_address(&principal)?;
		let permissions = pure::permissions_from_flags(&permissions, &[])?;
		let target = target
			.map(|target| pure::account_from_address(&target))
			.transpose()?;
		let operation = pure::op_modify_permissions(principal, permissions, AdjustMethod::from(method), target);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_set_info(
		&self,
		name: String,
		description: String,
		metadata: String,
		default_permission: Vec<String>,
	) -> Result<(), CodedError> {
		let default_permission = match default_permission.is_empty() {
			true => None,
			false => Some(pure::permissions_from_flags(&default_permission, &[])?),
		};
		let operation = pure::op_set_info(name, description, metadata, default_permission);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_set_rep(&self, rep: String) -> Result<(), CodedError> {
		let rep = pure::account_from_address(&rep)?;
		let operation = pure::op_set_rep(rep);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn build_and_sign(&self) -> Result<String, CodedError> {
		let builder = self
			.builder
			.borrow_mut()
			.take()
			.ok_or_else(builder_consumed)?;
		let unsigned = pure::build_unsigned(builder)?;
		let signed = pure::sign_unsigned(unsigned)?;
		Ok(pure::block_to_hex(&signed))
	}
}

export!(Component);
