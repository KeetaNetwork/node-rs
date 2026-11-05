//! Arbiter-released escrow.
//!
//! Holds native Keeta tokens (attached as funds) and cw20 tokens (sent with
//! `Cw20ExecuteMsg::Send`). The arbiter releases everything to the
//! recipient; after expiry anyone can refund everything to whoever
//! instantiated the escrow.
//!
//! Exercises: bank queries, Keeta queries, `KeetaMsg::Send` with an
//! `external` memo, and cross-contract `WasmMsg::Execute`.

use cosmwasm_std::{
	entry_point, to_json_binary, Addr, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Order, Response,
	StdError, StdResult, Storage, Timestamp, Uint128, WasmMsg,
};
use cw20::{Cw20ExecuteMsg, Cw20ReceiveMsg};
use cw_storage_plus::{Item, Map};
use keetanetwork_contract_std::{KeetaMsg, KeetaQuerier, KeetaQuery};
use serde::{Deserialize, Serialize};

type KeetaResponse = Response<KeetaMsg>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
	pub arbiter: Addr,
	pub recipient: Addr,
	pub source: Addr,
	pub expires_at: Timestamp,
	pub closed: bool,
}

const CONFIG: Item<Config> = Item::new("config");
const NATIVE: Map<&str, Uint128> = Map::new("native");
const CW20: Map<&Addr, Uint128> = Map::new("cw20");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
	pub arbiter: String,
	pub recipient: String,
	pub expires_at: Timestamp,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
	/// Add the attached native funds.
	Deposit {},
	/// cw20 deposit hook.
	Receive(Cw20ReceiveMsg),
	/// Arbiter only: release everything to the recipient.
	Approve { memo: Option<String> },
	/// After expiry: return everything to the source.
	Refund {},
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
	Config {},
	Holdings {},
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Cw20Holding {
	pub token: Addr,
	pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct HoldingsResponse {
	pub native: Vec<Coin>,
	pub cw20: Vec<Cw20Holding>,
}

#[entry_point]
pub fn instantiate(
	deps: DepsMut<KeetaQuery>,
	env: Env,
	info: MessageInfo,
	msg: InstantiateMsg,
) -> StdResult<KeetaResponse> {
	if msg.expires_at <= env.block.time {
		return Err(StdError::generic_err("expiry must be in the future"));
	}
	let config = Config {
		arbiter: deps.api.addr_validate(&msg.arbiter)?,
		recipient: deps.api.addr_validate(&msg.recipient)?,
		source: info.sender,
		expires_at: msg.expires_at,
		closed: false,
	};
	CONFIG.save(deps.storage, &config)?;
	record_native(deps.storage, &info.funds)?;

	Ok(Response::new()
		.add_attribute("action", "instantiate")
		.add_attribute("arbiter", config.arbiter)
		.add_attribute("recipient", config.recipient))
}

#[entry_point]
pub fn execute(deps: DepsMut<KeetaQuery>, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<KeetaResponse> {
	let mut config = CONFIG.load(deps.storage)?;
	if config.closed {
		return Err(StdError::generic_err("escrow is closed"));
	}

	match msg {
		ExecuteMsg::Deposit {} => {
			if info.funds.is_empty() {
				return Err(StdError::generic_err("no funds attached"));
			}
			record_native(deps.storage, &info.funds)?;
			Ok(Response::new().add_attribute("action", "deposit"))
		}
		ExecuteMsg::Receive(Cw20ReceiveMsg { amount, .. }) => {
			// The cw20 contract is the caller.
			CW20.update(deps.storage, &info.sender, |held| -> StdResult<_> {
				Ok(held.unwrap_or_default().checked_add(amount)?)
			})?;
			Ok(Response::new()
				.add_attribute("action", "receive_cw20")
				.add_attribute("token", info.sender))
		}
		ExecuteMsg::Approve { memo } => {
			if info.sender != config.arbiter {
				return Err(StdError::generic_err("only the arbiter can approve"));
			}
			// Keeta-specific read: surface the recipient's on-chain name.
			let recipient_info = deps.querier.keeta_account_info(config.recipient.as_str())?;
			let messages = release(deps.as_ref(), &env, &config.recipient, memo)?;
			config.closed = true;
			CONFIG.save(deps.storage, &config)?;
			Ok(Response::new()
				.add_messages(messages)
				.add_attribute("action", "approve")
				.add_attribute("recipient_name", recipient_info.name))
		}
		ExecuteMsg::Refund {} => {
			if env.block.time < config.expires_at {
				return Err(StdError::generic_err("escrow has not expired"));
			}
			let messages = release(deps.as_ref(), &env, &config.source, Some("REFUND".into()))?;
			config.closed = true;
			CONFIG.save(deps.storage, &config)?;
			Ok(Response::new()
				.add_messages(messages)
				.add_attribute("action", "refund"))
		}
	}
}

#[entry_point]
pub fn query(deps: Deps<KeetaQuery>, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
	match msg {
		QueryMsg::Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
		QueryMsg::Holdings {} => to_json_binary(&holdings(deps)?),
	}
}

fn record_native(storage: &mut dyn Storage, funds: &[Coin]) -> StdResult<()> {
	for coin in funds {
		NATIVE.update(storage, &coin.denom, |held| -> StdResult<_> {
			Ok(held.unwrap_or_default().checked_add(coin.amount)?)
		})?;
	}
	Ok(())
}

fn holdings(deps: Deps<KeetaQuery>) -> StdResult<HoldingsResponse> {
	let native = NATIVE
		.range(deps.storage, None, None, Order::Ascending)
		.map(|entry| entry.map(|(denom, amount)| Coin { denom, amount }))
		.collect::<StdResult<_>>()?;
	let cw20 = CW20
		.range(deps.storage, None, None, Order::Ascending)
		.map(|entry| entry.map(|(token, amount)| Cw20Holding { token, amount }))
		.collect::<StdResult<_>>()?;
	Ok(HoldingsResponse { native, cw20 })
}

fn release(deps: Deps<KeetaQuery>, env: &Env, to: &Addr, memo: Option<String>) -> StdResult<Vec<CosmosMsg<KeetaMsg>>> {
	let held = holdings(deps)?;
	let mut messages = Vec::new();

	for coin in held.native {
		// Cross-check the escrow's own bookkeeping against the ledger.
		let on_ledger = deps
			.querier
			.query_balance(&env.contract.address, &coin.denom)?;
		if on_ledger.amount < coin.amount {
			return Err(StdError::generic_err(format!("ledger holds less {} than recorded", coin.denom)));
		}
		messages.push(
			KeetaMsg::Send {
				to: to.to_string(),
				token: coin.denom,
				amount: coin.amount.into(),
				external: memo.clone(),
			}
			.into(),
		);
	}

	for holding in held.cw20 {
		messages.push(
			WasmMsg::Execute {
				contract_addr: holding.token.into_string(),
				msg: to_json_binary(&Cw20ExecuteMsg::Transfer { recipient: to.to_string(), amount: holding.amount })?,
				funds: vec![],
			}
			.into(),
		);
	}

	Ok(messages)
}
