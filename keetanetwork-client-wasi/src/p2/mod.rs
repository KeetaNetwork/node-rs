//! WASI Preview 2 component exposing the networked KeetaNet client.

use core::cell::RefCell;
use core::future::Future;
use core::str::FromStr;
use std::sync::Arc;

use keetanetwork_account::{AccountPublicKey, GenericAccount, KeyPairType};
use keetanetwork_bindings::parse::{self, amount as parse_amount, amount_to_string};
use keetanetwork_bindings::permissions as bindings_permissions;
use keetanetwork_block::{
	AccountRef, AdjustMethod, BaseFlag, BlockBuilder, BlockHash, CertificateDer, CertificateOrHash,
	IdentifierCreateArguments, IntermediateCertificates, ManageCertificate, ModifyPermissions,
	ModifyPermissionsPrincipal, MultisigCreateArguments, Permissions, SetInfo,
};
use keetanetwork_client::{
	AcceptSwapRequest, AccountInfo as CoreInfo, AccountState as CoreState, Acl as CoreAcl,
	AclPrincipal as CoreAclPrincipal, BlockEffects as CoreBlockEffects, Certificate as CoreCertificate, ChainQuery,
	ClientConfig, ClientError, CreateSwapRequest, HistoryEntry as CoreHistory, HistoryQuery, KeetaClient,
	LedgerChecksum as CoreChecksum, LedgerSide, RepPart, Representative as CoreRep, Runtime, SwapExpectation,
	SwapTokenAmount, TokenBalance as CoreTokenBalance, TransactionBuilder, TransmitOptions, UserClient, VoteBlockHash,
	WasiRuntime, WasiTransportFactory,
};
use keetanetwork_x509::certificates::Certificate as X509Certificate;
use num_bigint::BigInt;
use wstd::runtime::block_on;

use crate::pure;

wit_bindgen::generate!({
	world: "keeta-client",
	path: "wit",
});

use exports::keeta::client::crypto::{
	Account as WitAccount, AccountBorrow, AccountKind as WitAccountKind, Certificate as WitCertificate,
	Guest as CryptoGuest, GuestAccount, GuestCertificate, KeyAlgorithm as WitKeyAlgorithm,
};
use exports::keeta::client::node::{
	AccountInfo, AccountState, Acl, AclCertificatePrincipal as WitAclCertificatePrincipal,
	AclPrincipal as WitAclPrincipal, AdjustMethod as WitAdjustMethod, BasePermission as WitBasePermission,
	BlockBuilder as BlockBuilderResource, BlockEffects as WitBlockEffects, Certificate, ChainPage,
	ChainQuery as WitChainQuery, CodedError, Guest, GuestBlockBuilder, GuestClient, GuestTransaction, GuestUserClient,
	HeadInfo, HistoryEntry, HistoryQuery as WitHistoryQuery, IdentifierKind as WitIdentifierKind, LedgerChecksum,
	LedgerSide as WitLedgerSide, Representative, StapleEffects as WitStapleEffects,
	SwapExpectation as WitSwapExpectation, SwapTokenAmount as WitSwapTokenAmount, TokenBalance,
	Transaction as TransactionResource, UserClient as UserClientResource,
};

impl From<WitLedgerSide> for LedgerSide {
	fn from(side: WitLedgerSide) -> Self {
		match side {
			WitLedgerSide::Main => LedgerSide::Main,
			WitLedgerSide::Side => LedgerSide::Side,
			WitLedgerSide::Both => LedgerSide::Both,
		}
	}
}

/// The typed account behind a borrowed WIT account resource.
fn account_of(resource: AccountBorrow<'_>) -> AccountRef {
	Arc::clone(&resource.get::<AccountResource>().account)
}

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

/// Parse a hex block hash crossing the WIT boundary.
fn parse_block_hash(value: &str) -> Result<BlockHash, CodedError> {
	Ok(BlockHash::from(decode_hash(value)?))
}

/// Parse a hex history cursor (staple id) crossing the WIT boundary.
fn parse_history_cursor(value: &str) -> Result<VoteBlockHash, CodedError> {
	Ok(VoteBlockHash::from(decode_hash(value)?))
}

struct Component;

impl Guest for Component {
	type Client = NodeClient;
	type UserClient = AccountClient;
	type Transaction = TransactionState;
	type BlockBuilder = BuilderState;

	fn derive_identifier(
		signer: AccountBorrow<'_>,
		kind: WitIdentifierKind,
		previous: Option<String>,
		op_index: u32,
	) -> Result<String, CodedError> {
		let account = &signer.get::<AccountResource>().account;
		let previous = previous.map(|hash| decode_hash(&hash)).transpose()?;
		let identifier = pure::generate_identifier(account, kind.into(), previous, op_index)?;
		Ok(pure::account_address(&identifier))
	}
}

// ---------------------------------------------------------------------------
// crypto interface: account + certificate resources
// ---------------------------------------------------------------------------

/// Multiply Unix `seconds` into milliseconds for the millisecond-based cores,
/// rejecting a value that would overflow.
fn seconds_to_millis(seconds: i64) -> Result<i64, CodedError> {
	seconds
		.checked_mul(1000)
		.ok_or_else(|| CodedError { code: "INVALID_DATE".into(), message: "unix seconds out of range".into() })
}

impl CryptoGuest for Component {
	type Account = AccountResource;
	type Certificate = CertificateResource;
}

/// A signing or read-only account, stored erased over its algorithm.
struct AccountResource {
	account: AccountRef,
}

impl GuestAccount for AccountResource {
	fn from_seed(seed: String, index: u32, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = pure::account_from_seed(&seed, index, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_private_key(key: String, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = pure::account_from_private_key(&key, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_passphrase(words: Vec<String>, index: u32, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = pure::account_from_passphrase(words, index, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_public_key(key: String, algorithm: WitKeyAlgorithm) -> Result<WitAccount, CodedError> {
		let account = pure::account_from_public_key(&key, algorithm_name(algorithm))?;
		Ok(WitAccount::new(Self { account }))
	}

	fn from_address(address: String) -> Result<WitAccount, CodedError> {
		let account = pure::account_from_address(&address)?;
		Ok(WitAccount::new(Self { account }))
	}

	fn generate_seed() -> String {
		pure::generate_seed().unwrap_or_default()
	}

	fn generate_passphrase() -> Vec<String> {
		pure::generate_passphrase().unwrap_or_default()
	}

	fn address(&self) -> String {
		pure::account_address(&self.account)
	}

	fn kind(&self) -> WitAccountKind {
		match self.account.to_keypair_type() {
			KeyPairType::ED25519 => WitAccountKind::Signing(WitKeyAlgorithm::Ed25519),
			KeyPairType::ECDSASECP256K1 => WitAccountKind::Signing(WitKeyAlgorithm::EcdsaSecp256k1),
			KeyPairType::ECDSASECP256R1 => WitAccountKind::Signing(WitKeyAlgorithm::EcdsaSecp256r1),
			KeyPairType::NETWORK => WitAccountKind::Identifier(WitIdentifierKind::Network),
			KeyPairType::TOKEN => WitAccountKind::Identifier(WitIdentifierKind::Token),
			KeyPairType::STORAGE => WitAccountKind::Identifier(WitIdentifierKind::Storage),
			KeyPairType::MULTISIG => WitAccountKind::Identifier(WitIdentifierKind::Multisig),
		}
	}

	fn public_key(&self) -> String {
		pure::account_public_key(&self.account)
	}

	fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(pure::account_sign(&self.account, &message)?)
	}

	fn verify(&self, message: Vec<u8>, signature: Vec<u8>) -> bool {
		pure::account_verify(&self.account, &message, &signature)
	}

	fn encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(pure::account_encrypt(&self.account, &plaintext)?)
	}

	fn decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, CodedError> {
		Ok(pure::account_decrypt(&self.account, &ciphertext)?)
	}
}

/// A base X.509 certificate: a provider CA, a trust root, or an intermediate.
struct CertificateResource {
	certificate: X509Certificate,
}

impl GuestCertificate for CertificateResource {
	fn parse(pem: String) -> Result<WitCertificate, CodedError> {
		let certificate = pure::certificate_from_pem(&pem)?;
		Ok(WitCertificate::new(Self { certificate }))
	}

	fn pem(&self) -> Result<String, CodedError> {
		Ok(pure::certificate_pem(&self.certificate)?)
	}

	fn valid_at(&self, unix_seconds: i64) -> bool {
		seconds_to_millis(unix_seconds)
			.ok()
			.and_then(|millis| pure::certificate_valid_at(&self.certificate, millis).ok())
			.unwrap_or(false)
	}

	fn subject(&self) -> String {
		pure::certificate_subject(&self.certificate)
	}

	fn issuer(&self) -> String {
		pure::certificate_issuer(&self.certificate)
	}

	fn serial(&self) -> String {
		pure::certificate_serial(&self.certificate)
	}

	fn not_before(&self) -> i64 {
		pure::certificate_not_before(&self.certificate)
	}

	fn not_after(&self) -> i64 {
		pure::certificate_not_after(&self.certificate)
	}

	fn subject_public_key(&self) -> Result<String, CodedError> {
		Ok(pure::certificate_subject_public_key(&self.certificate)?)
	}
}

/// The canonical name of a signing algorithm, as understood by the shared
/// account constructors.
fn algorithm_name(algorithm: WitKeyAlgorithm) -> &'static str {
	match algorithm {
		WitKeyAlgorithm::Ed25519 => "ed25519",
		WitKeyAlgorithm::EcdsaSecp256k1 => "ecdsa_secp256k1",
		WitKeyAlgorithm::EcdsaSecp256r1 => "ecdsa_secp256r1",
	}
}

impl From<WitIdentifierKind> for KeyPairType {
	fn from(kind: WitIdentifierKind) -> Self {
		match kind {
			WitIdentifierKind::Network => KeyPairType::NETWORK,
			WitIdentifierKind::Token => KeyPairType::TOKEN,
			WitIdentifierKind::Storage => KeyPairType::STORAGE,
			WitIdentifierKind::Multisig => KeyPairType::MULTISIG,
		}
	}
}

/// The per-flag mapping between the WIT flags type and the domain base
/// flags, in on-chain bit order.
const PERMISSION_FLAGS: [(WitBasePermission, BaseFlag); 15] = [
	(WitBasePermission::ACCESS, BaseFlag::Access),
	(WitBasePermission::OWNER, BaseFlag::Owner),
	(WitBasePermission::ADMIN, BaseFlag::Admin),
	(WitBasePermission::UPDATE_INFO, BaseFlag::UpdateInfo),
	(WitBasePermission::SEND_ON_BEHALF, BaseFlag::SendOnBehalf),
	(WitBasePermission::TOKEN_ADMIN_CREATE, BaseFlag::TokenAdminCreate),
	(WitBasePermission::TOKEN_ADMIN_SUPPLY, BaseFlag::TokenAdminSupply),
	(WitBasePermission::TOKEN_ADMIN_MODIFY_BALANCE, BaseFlag::TokenAdminModifyBalance),
	(WitBasePermission::STORAGE_CREATE, BaseFlag::StorageCreate),
	(WitBasePermission::STORAGE_CAN_HOLD, BaseFlag::StorageCanHold),
	(WitBasePermission::STORAGE_DEPOSIT, BaseFlag::StorageDeposit),
	(WitBasePermission::PERMISSION_DELEGATE_ADD, BaseFlag::PermissionDelegateAdd),
	(WitBasePermission::PERMISSION_DELEGATE_REMOVE, BaseFlag::PermissionDelegateRemove),
	(WitBasePermission::MANAGE_CERTIFICATE, BaseFlag::ManageCertificate),
	(WitBasePermission::MULTISIG_SIGNER, BaseFlag::MultisigSigner),
];

/// Build a domain permission set from the WIT base-permission flags.
fn permissions_of(flags: WitBasePermission) -> Result<Permissions, CodedError> {
	let flags: Vec<BaseFlag> = PERMISSION_FLAGS
		.iter()
		.filter(|(wit, _)| flags.contains(*wit))
		.map(|&(_, base)| base)
		.collect();

	Ok(bindings_permissions::from_flags(&flags, &[])?)
}

/// Project a domain permission set onto the WIT base-permission flags.
fn wit_permissions_of(permissions: &Permissions) -> WitBasePermission {
	let flags = permissions.base().flags();
	PERMISSION_FLAGS
		.iter()
		.filter(|(_, base)| flags.contains(base))
		.fold(WitBasePermission::empty(), |set, &(wit, _)| set | wit)
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
		let account = rep.account.to_string();
		let weight = amount_to_string(rep.weight);

		Self { account, weight, api_url: rep.api_url }
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
			representative: state
				.representative
				.map(|representative| representative.to_string()),
			head: state.head.map(|head| head.to_string()),
			height: state.height.map(amount_to_string),
			info: state.info.map(AccountInfo::from),
			supply: state.supply.map(amount_to_string),
			balances: state.balances.into_iter().map(TokenBalance::from).collect(),
		}
	}
}

impl From<CoreChecksum> for LedgerChecksum {
	fn from(checksum: CoreChecksum) -> Self {
		Self {
			checksum: amount_to_string(checksum.checksum),
			moment: checksum.moment.map(|moment| moment.to_string()),
			moment_range: checksum.moment_range,
		}
	}
}

impl From<CoreTokenBalance> for TokenBalance {
	fn from(balance: CoreTokenBalance) -> Self {
		let amount = amount_to_string(balance.balance);
		let token = balance.token.to_string();

		Self { token, amount }
	}
}

impl From<CoreHistory> for HistoryEntry {
	fn from(entry: CoreHistory) -> Self {
		Self {
			staple: pure::staple_to_hex(&entry.staple),
			id: entry.id.map(|id| id.to_string()),
			timestamp: entry.timestamp.map(|moment| moment.to_string()),
		}
	}
}

impl From<&CoreBlockEffects> for WitBlockEffects {
	fn from(effects: &CoreBlockEffects) -> Self {
		Self {
			block: pure::block_to_hex(&effects.block),
			operation_indexes: effects
				.operation_indexes
				.iter()
				.map(|&index| index as u32)
				.collect(),
		}
	}
}

impl TryFrom<WitChainQuery> for ChainQuery {
	type Error = CodedError;

	fn try_from(query: WitChainQuery) -> Result<Self, Self::Error> {
		let start = query.start.as_deref().map(parse_block_hash).transpose()?;
		let end = query.end.as_deref().map(parse_block_hash).transpose()?;

		Ok(Self { start, end, limit: query.limit })
	}
}

impl TryFrom<WitHistoryQuery> for HistoryQuery {
	type Error = CodedError;

	fn try_from(query: WitHistoryQuery) -> Result<Self, Self::Error> {
		let start = query
			.start
			.as_deref()
			.map(parse_history_cursor)
			.transpose()?;

		Ok(Self { start, limit: query.limit })
	}
}

impl From<&CoreAclPrincipal> for WitAclPrincipal {
	fn from(principal: &CoreAclPrincipal) -> Self {
		match principal {
			CoreAclPrincipal::Account(account) => Self::Account(account.to_string()),
			CoreAclPrincipal::Certificate { hash, account } => Self::Certificate(WitAclCertificatePrincipal {
				certificate: hex::encode(hash),
				account: account.to_string(),
			}),
		}
	}
}

impl From<CoreAcl> for Acl {
	fn from(acl: CoreAcl) -> Self {
		Self {
			principal: acl.principal.as_ref().map(WitAclPrincipal::from),
			entity: acl.entity.map(|entity| entity.to_string()),
			target: acl.target.map(|target| target.to_string()),
			permissions: wit_permissions_of(&acl.permissions),
			external_permissions: bindings_permissions::offsets(&acl.permissions),
		}
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

	fn account_balance(&self, account: AccountBorrow<'_>, token: AccountBorrow<'_>) -> Result<String, CodedError> {
		let (account, token) = (account_of(account), account_of(token));
		Ok(amount_to_string(run(self.inner.balance(&*account, &*token))?))
	}

	fn account_balances(&self, account: AccountBorrow<'_>) -> Result<Vec<TokenBalance>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.balances(&*account))?
			.into_iter()
			.map(TokenBalance::from)
			.collect())
	}

	fn token_supply(&self, token: AccountBorrow<'_>) -> Result<Option<String>, CodedError> {
		let token = account_of(token);
		Ok(run(self.inner.token_supply(&*token))?.map(amount_to_string))
	}

	fn account_state(&self, account: AccountBorrow<'_>) -> Result<AccountState, CodedError> {
		let account = account_of(account);
		Ok(AccountState::from(run(self.inner.state(&*account))?))
	}

	fn head_block(&self, account: AccountBorrow<'_>) -> Result<Option<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.head_block(&*account))?.map(|block| pure::block_to_hex(&block)))
	}

	fn block(&self, blockhash: String, side: Option<WitLedgerSide>) -> Result<Option<String>, CodedError> {
		let blockhash = parse_block_hash(&blockhash)?;
		Ok(run(self.inner.block(blockhash, side.map(Into::into)))?.map(|block| pure::block_to_hex(&block)))
	}

	fn vote_staple(&self, blockhash: String, side: Option<WitLedgerSide>) -> Result<Option<String>, CodedError> {
		let blockhash = parse_block_hash(&blockhash)?;
		Ok(run(self.inner.vote_staple(blockhash, side.map(Into::into)))?.map(|staple| pure::staple_to_hex(&staple)))
	}

	fn representative(&self, rep: AccountBorrow<'_>) -> Result<Representative, CodedError> {
		let rep = account_of(rep);
		Ok(Representative::from(run(self.inner.representative(&*rep))?))
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

	fn chain(&self, account: AccountBorrow<'_>) -> Result<Vec<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.chain(&*account))?
			.iter()
			.map(pure::block_to_hex)
			.collect())
	}

	fn chain_page(&self, account: AccountBorrow<'_>, query: WitChainQuery) -> Result<ChainPage, CodedError> {
		let account = account_of(account);
		let page = run(self
			.inner
			.chain_page_cursor(&*account, ChainQuery::try_from(query)?))?;
		Ok(ChainPage {
			blocks: page.blocks.iter().map(pure::block_to_hex).collect(),
			next_key: page.next_key.map(|key| key.to_string()),
		})
	}

	fn chain_all(&self, account: AccountBorrow<'_>, page_limit: u32) -> Result<Vec<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.chain_all(&*account, page_limit))?
			.iter()
			.map(pure::block_to_hex)
			.collect())
	}

	fn history(&self, account: AccountBorrow<'_>) -> Result<Vec<HistoryEntry>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.history(&*account))?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn pending_block(&self, account: AccountBorrow<'_>) -> Result<Option<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.pending_block(&*account))?.map(|block| pure::block_to_hex(&block)))
	}

	fn account_head_info(&self, account: AccountBorrow<'_>) -> Result<Option<HeadInfo>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.account_head_info(&*account))?
			.map(|(block, height)| HeadInfo { block: pure::block_to_hex(&block), height: amount_to_string(height) }))
	}

	fn account_states(&self, accounts: Vec<AccountBorrow<'_>>) -> Result<Vec<AccountState>, CodedError> {
		let accounts: Vec<AccountRef> = accounts.into_iter().map(account_of).collect();
		let refs: Vec<&GenericAccount> = accounts.iter().map(|account| &**account).collect();
		Ok(run(self.inner.states(&refs))?
			.into_iter()
			.map(AccountState::from)
			.collect())
	}

	fn successor_block(&self, blockhash: String) -> Result<Option<String>, CodedError> {
		let blockhash = parse_block_hash(&blockhash)?;
		Ok(run(self.inner.successor_block(blockhash))?.map(|block| pure::block_to_hex(&block)))
	}

	fn block_by_idempotent(
		&self,
		account: AccountBorrow<'_>,
		key: String,
		side: Option<WitLedgerSide>,
	) -> Result<Option<String>, CodedError> {
		let account = account_of(account);
		let side = side.map(Into::into);
		Ok(run(self.inner.block_by_idempotent(&*account, key, side))?.map(|block| pure::block_to_hex(&block)))
	}

	fn history_page(
		&self,
		account: AccountBorrow<'_>,
		query: WitHistoryQuery,
	) -> Result<Vec<HistoryEntry>, CodedError> {
		let account = account_of(account);
		let entries = run(self
			.inner
			.history_page(&*account, HistoryQuery::try_from(query)?))?;
		Ok(entries.into_iter().map(HistoryEntry::from).collect())
	}

	fn history_all(&self, account: AccountBorrow<'_>, page_limit: u32) -> Result<Vec<HistoryEntry>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.history_all(&*account, page_limit))?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn node_representative(&self) -> Result<Representative, CodedError> {
		Ok(Representative::from(run(self.inner.node_representative())?))
	}

	fn acls_by_principal(&self, account: AccountBorrow<'_>) -> Result<Vec<Acl>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.acls_by_principal(&*account))?
			.into_iter()
			.map(Acl::from)
			.collect())
	}

	fn acls_by_entity(&self, account: AccountBorrow<'_>) -> Result<Vec<Acl>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.acls_by_entity(&*account))?
			.into_iter()
			.map(Acl::from)
			.collect())
	}

	fn certificates(&self, account: AccountBorrow<'_>) -> Result<Vec<Certificate>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.certificates(&*account))?
			.into_iter()
			.map(Certificate::from)
			.collect())
	}

	fn certificate(&self, account: AccountBorrow<'_>, hash: String) -> Result<Option<Certificate>, CodedError> {
		let account = account_of(account);
		let hash = decode_hash(&hash)?;
		Ok(run(self.inner.certificate(&*account, hash))?.map(Certificate::from))
	}

	fn global_history(&self) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.global_history())?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn global_history_page(&self, query: WitHistoryQuery) -> Result<Vec<HistoryEntry>, CodedError> {
		let entries = run(self
			.inner
			.global_history_page(HistoryQuery::try_from(query)?))?;
		Ok(entries.into_iter().map(HistoryEntry::from).collect())
	}

	fn vote_staples_after(&self, start: String) -> Result<Vec<String>, CodedError> {
		let start = parse::moment(&start)?;
		Ok(run(self.inner.vote_staples_after(start))?
			.iter()
			.map(pure::staple_to_hex)
			.collect())
	}

	fn vote_staples_after_page(&self, start: String, limit: Option<i64>) -> Result<Vec<String>, CodedError> {
		let start = parse::moment(&start)?;
		Ok(run(self.inner.vote_staples_after_page(start, limit))?
			.iter()
			.map(pure::staple_to_hex)
			.collect())
	}

	fn sync_account(&self, account: AccountBorrow<'_>, publish: bool) -> Result<Option<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self.inner.sync_account(&account, publish))?.map(|staple| pure::staple_to_hex(&staple)))
	}

	fn recover_account(&self, account: AccountBorrow<'_>, publish: bool) -> Result<Option<String>, CodedError> {
		let account = account_of(account);
		Ok(run(self
			.inner
			.recover_account(&account, publish, TransmitOptions::default()))?
		.map(|staple| pure::staple_to_hex(&staple)))
	}
}

/// A read-only [`UserClient`] scoped to one operating account.
struct AccountClient {
	inner: UserClient,
}

impl GuestUserClient for AccountClient {
	fn read_only(base_url: String, address: AccountBorrow<'_>) -> Result<UserClientResource, CodedError> {
		let account = account_of(address);
		let inner = UserClient::from_parts(single_rep_client(base_url), None).with_account(account);
		Ok(UserClientResource::new(Self { inner }))
	}

	fn with_account(
		base_url: String,
		signer: AccountBorrow<'_>,
		network: String,
	) -> Result<UserClientResource, CodedError> {
		let signer = account_of(signer);
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

	fn balance(&self, token: AccountBorrow<'_>) -> Result<String, CodedError> {
		let token = account_of(token);
		Ok(amount_to_string(run(self.inner.balance(&*token))?))
	}

	fn all_balances(&self) -> Result<Vec<TokenBalance>, CodedError> {
		Ok(run(self.inner.all_balances())?
			.into_iter()
			.map(TokenBalance::from)
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
		let blocks = run(self.inner.chain_page(ChainQuery::try_from(query)?))?;
		Ok(blocks.iter().map(pure::block_to_hex).collect())
	}

	fn chain_all(&self, page_limit: u32) -> Result<Vec<String>, CodedError> {
		Ok(run(self.inner.chain_all(page_limit))?
			.iter()
			.map(pure::block_to_hex)
			.collect())
	}

	fn history(&self) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.history())?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn history_page(&self, query: WitHistoryQuery) -> Result<Vec<HistoryEntry>, CodedError> {
		let entries = run(self.inner.history_page(HistoryQuery::try_from(query)?))?;
		Ok(entries.into_iter().map(HistoryEntry::from).collect())
	}

	fn history_all(&self, page_limit: u32) -> Result<Vec<HistoryEntry>, CodedError> {
		Ok(run(self.inner.history_all(page_limit))?
			.into_iter()
			.map(HistoryEntry::from)
			.collect())
	}

	fn pending_block(&self) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.pending_block())?.map(|block| pure::block_to_hex(&block)))
	}

	fn block(&self, blockhash: String, side: Option<WitLedgerSide>) -> Result<Option<String>, CodedError> {
		let blockhash = parse_block_hash(&blockhash)?;
		Ok(run(self.inner.block(blockhash, side.map(Into::into)))?.map(|block| pure::block_to_hex(&block)))
	}

	fn block_from_idempotent(&self, key: String, side: Option<WitLedgerSide>) -> Result<Option<String>, CodedError> {
		let side = side.map(Into::into);
		Ok(run(self.inner.block_from_idempotent(key, side))?.map(|block| pure::block_to_hex(&block)))
	}

	fn staple_effects(&self, staples: Vec<String>) -> Result<Vec<WitStapleEffects>, CodedError> {
		let moment = WasiRuntime.unix_millis();
		let staples = staples
			.iter()
			.map(|staple| pure::staple_from_hex(staple, moment))
			.collect::<Result<Vec<_>, _>>()?;

		let effects = self
			.inner
			.staple_effects(&staples)
			.map_err(CodedError::from)?;
		Ok(effects
			.into_iter()
			.map(|(id, blocks)| WitStapleEffects {
				id: id.to_string(),
				blocks: blocks.iter().map(WitBlockEffects::from).collect(),
			})
			.collect())
	}

	fn acls(&self) -> Result<Vec<Acl>, CodedError> {
		Ok(run(self.inner.acls())?.into_iter().map(Acl::from).collect())
	}

	fn acls_by_entity(&self) -> Result<Vec<Acl>, CodedError> {
		Ok(run(self.inner.acls_by_entity())?
			.into_iter()
			.map(Acl::from)
			.collect())
	}

	fn certificates(&self) -> Result<Vec<Certificate>, CodedError> {
		Ok(run(self.inner.certificates())?
			.into_iter()
			.map(Certificate::from)
			.collect())
	}

	fn certificate(&self, hash: String) -> Result<Option<Certificate>, CodedError> {
		let hash = decode_hash(&hash)?;
		Ok(run(self.inner.certificate(hash))?.map(Certificate::from))
	}

	fn sync(&self, publish: bool) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.sync(publish))?.map(|staple| pure::staple_to_hex(&staple)))
	}

	fn recover(&self, publish: bool) -> Result<Option<String>, CodedError> {
		Ok(run(self.inner.recover(publish))?.map(|staple| pure::staple_to_hex(&staple)))
	}

	fn send(&self, to: AccountBorrow<'_>, token: AccountBorrow<'_>, amount: String) -> Result<bool, CodedError> {
		let to = account_of(to);
		let token = account_of(token);
		let amount = parse_amount(&amount)?;

		run(self.inner.send(&to, &token, amount))
	}

	fn send_external(
		&self,
		to: AccountBorrow<'_>,
		token: AccountBorrow<'_>,
		amount: String,
		external: String,
	) -> Result<bool, CodedError> {
		let to = account_of(to);
		let token = account_of(token);
		let amount = parse_amount(&amount)?;

		run(self.inner.send_external(&to, &token, amount, external))
	}

	fn set_rep(&self, rep: AccountBorrow<'_>) -> Result<bool, CodedError> {
		let rep = account_of(rep);
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
		token: AccountBorrow<'_>,
		holder: Option<AccountBorrow<'_>>,
		amount: String,
		method: WitAdjustMethod,
	) -> Result<bool, CodedError> {
		let token = account_of(token);
		let holder = holder.map(account_of);
		let amount = parse_amount(&amount)?;

		run(self
			.inner
			.modify_token_supply_and_balance(&token, holder.as_ref(), amount, AdjustMethod::from(method)))
	}

	fn update_permissions(
		&self,
		principal: AccountBorrow<'_>,
		method: WitAdjustMethod,
		permissions: WitBasePermission,
		target: Option<AccountBorrow<'_>>,
	) -> Result<bool, CodedError> {
		let principal = ModifyPermissionsPrincipal::Account(account_of(principal));
		let permissions = match permissions.is_empty() {
			true => None,
			false => Some(permissions_of(permissions)?),
		};

		let target = target.map(account_of);
		let change = ModifyPermissions { principal, method: AdjustMethod::from(method), permissions, target };
		run(self.inner.update_permissions(change))
	}

	fn generate_multisig(&self, signers: Vec<AccountBorrow<'_>>, quorum: u32) -> Result<String, CodedError> {
		let signers = signers.into_iter().map(account_of).collect();
		let arguments = IdentifierCreateArguments::Multisig(MultisigCreateArguments { signers, quorum: quorum.into() });
		let identifier = run(self
			.inner
			.generate_identifier(KeyPairType::MULTISIG, Some(arguments)))?;
		Ok(pure::account_address(&identifier))
	}

	fn generate_identifier(&self, kind: WitIdentifierKind) -> Result<String, CodedError> {
		// Multisig identifiers require create arguments, supplied only by the
		// dedicated generate-multisig path.
		if kind == WitIdentifierKind::Multisig {
			return Err(CodedError {
				code: "INVALID_IDENTIFIER_TYPE".into(),
				message: "multisig identifiers are created through generate-multisig".into(),
			});
		}

		let identifier = run(self.inner.generate_identifier(kind.into(), None))?;
		Ok(pure::account_address(&identifier))
	}

	fn create_swap(
		&self,
		counterparty: AccountBorrow<'_>,
		send_token: AccountBorrow<'_>,
		send_amount: String,
		receive_token: AccountBorrow<'_>,
		receive_amount: String,
		receive_exact: bool,
	) -> Result<String, CodedError> {
		let request = CreateSwapRequest {
			counterparty: account_of(counterparty),
			send_token: account_of(send_token),
			send_amount: parse_amount(&send_amount)?,
			receive_token: account_of(receive_token),
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
	fn send(&self, to: AccountBorrow<'_>, token: AccountBorrow<'_>, amount: String) -> Result<(), CodedError> {
		let to = account_of(to);
		let token = account_of(token);
		let amount = parse_amount(&amount)?;

		self.builder.borrow_mut().send(&to, &token, amount);

		Ok(())
	}

	fn send_external(
		&self,
		to: AccountBorrow<'_>,
		token: AccountBorrow<'_>,
		amount: String,
		external: String,
	) -> Result<(), CodedError> {
		let to = account_of(to);
		let token = account_of(token);
		let amount = parse_amount(&amount)?;

		self.builder
			.borrow_mut()
			.send_external(&to, &token, amount, external);

		Ok(())
	}

	fn set_rep(&self, rep: AccountBorrow<'_>) -> Result<(), CodedError> {
		let rep = account_of(rep);

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

/// A low-level, block assembler. `BlockBuilder` mutators consume `self`,
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
	fn new(network: String, account: AccountBorrow<'_>) -> Result<BlockBuilderResource, CodedError> {
		let account = account_of(account);
		let network = BigInt::from_str(&network).map_err(|_| CodedError {
			code: "INVALID_INTEGER".into(),
			message: "network must be a decimal integer".into(),
		})?;
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

	fn signer_single(&self, signer: AccountBorrow<'_>) -> Result<(), CodedError> {
		let account = account_of(signer);
		let signer = pure::signer_single(account);
		self.stage(|builder| builder.with_signer(signer))
	}

	fn signer_multisig(&self, multisig: AccountBorrow<'_>, members: Vec<AccountBorrow<'_>>) -> Result<(), CodedError> {
		let multisig = account_of(multisig);
		let members = members.into_iter().map(account_of).collect();
		let signer = pure::signer_multisig(multisig, members);
		self.stage(|builder| builder.with_signer(signer))
	}

	fn op_create_multisig(
		&self,
		multisig: AccountBorrow<'_>,
		signers: Vec<AccountBorrow<'_>>,
		quorum: u32,
	) -> Result<(), CodedError> {
		let multisig = account_of(multisig);
		let signers = signers.into_iter().map(account_of).collect();
		let operation = pure::op_create_multisig(multisig, signers, quorum);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_modify_permissions(
		&self,
		principal: AccountBorrow<'_>,
		permissions: WitBasePermission,
		method: WitAdjustMethod,
		target: Option<AccountBorrow<'_>>,
	) -> Result<(), CodedError> {
		let principal = account_of(principal);
		let permissions = permissions_of(permissions)?;
		let target = target.map(account_of);

		let operation = pure::op_modify_permissions(principal, permissions, AdjustMethod::from(method), target);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_set_info(
		&self,
		name: String,
		description: String,
		metadata: String,
		default_permission: Option<WitBasePermission>,
	) -> Result<(), CodedError> {
		let default_permission = default_permission.map(permissions_of).transpose()?;
		let operation = pure::op_set_info(name, description, metadata, default_permission);
		self.stage(|builder| builder.with_operation(operation))
	}

	fn op_set_rep(&self, rep: AccountBorrow<'_>) -> Result<(), CodedError> {
		let rep = account_of(rep);
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
