//! A faucet that issues its own native Keeta token.
//!
//! On instantiation the contract creates a token and names its own account.
//! Anyone can claim a fixed amount once; the admin can airdrop to a list of
//! addresses (each mint is a submessage, so one bad address does not sink
//! the whole batch); holders can hand tokens back to be burned.
//!
//! Exercises: `KeetaMsg::{CreateToken, Mint, Burn, SetInfo}`, Keeta queries
//! from both `execute` and `query`, and submessages with `reply`.

use cosmwasm_std::{
	entry_point, to_json_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Reply, Response, StdError, StdResult,
	SubMsg, SubMsgResult, Uint128,
};
use cw_storage_plus::{Item, Map};
use keetanetwork_contract_std::{KeetaMsg, KeetaQuerier, KeetaQuery};
use serde::{Deserialize, Serialize};

type KeetaResponse = Response<KeetaMsg>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
	pub admin: Addr,
	pub subdenom: String,
	pub claim_amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct AirdropStats {
	pub succeeded: u64,
	pub failed: u64,
}

const CONFIG: Item<Config> = Item::new("config");
const CLAIMED: Map<&Addr, bool> = Map::new("claimed");
const AIRDROP: Item<AirdropStats> = Item::new("airdrop");

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
	pub subdenom: String,
	pub name: String,
	pub description: String,
	pub claim_amount: Uint128,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
	/// Claim `claim_amount` once per address.
	Claim {},
	/// Admin only: mint `claim_amount` to each recipient, tolerating failures.
	Airdrop { recipients: Vec<String> },
	/// Burn the faucet tokens attached as funds.
	Return {},
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
	/// Returns the token address as a string.
	Token {},
	/// Returns the token's total supply.
	Supply {},
	AirdropStats {},
	HasClaimed {
		address: String,
	},
}

#[entry_point]
pub fn instantiate(
	deps: DepsMut<KeetaQuery>,
	_env: Env,
	info: MessageInfo,
	msg: InstantiateMsg,
) -> StdResult<KeetaResponse> {
	CONFIG.save(
		deps.storage,
		&Config { admin: info.sender, subdenom: msg.subdenom.clone(), claim_amount: msg.claim_amount },
	)?;
	AIRDROP.save(deps.storage, &AirdropStats::default())?;

	Ok(Response::new()
		.add_message(KeetaMsg::CreateToken {
			subdenom: msg.subdenom,
			name: msg.name,
			description: msg.description.clone(),
		})
		.add_message(KeetaMsg::SetInfo {
			name: "FAUCET".into(),
			description: msg.description,
			metadata: String::new(),
		}))
}

#[entry_point]
pub fn execute(deps: DepsMut<KeetaQuery>, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<KeetaResponse> {
	let config = CONFIG.load(deps.storage)?;

	match msg {
		ExecuteMsg::Claim {} => {
			if CLAIMED.has(deps.storage, &info.sender) {
				return Err(StdError::generic_err("already claimed"));
			}
			CLAIMED.save(deps.storage, &info.sender, &true)?;
			Ok(Response::new()
				.add_message(mint(&config, info.sender.to_string()))
				.add_attribute("action", "claim"))
		}
		ExecuteMsg::Airdrop { recipients } => {
			if info.sender != config.admin {
				return Err(StdError::generic_err("only the admin can airdrop"));
			}
			// Addresses are deliberately not validated here: the host rejects
			// bad ones when the mint runs, and `reply` counts the failures.
			let submessages = recipients
				.into_iter()
				.enumerate()
				.map(|(index, to)| SubMsg::reply_always(mint(&config, to), index as u64));
			Ok(Response::new()
				.add_submessages(submessages)
				.add_attribute("action", "airdrop"))
		}
		ExecuteMsg::Return {} => {
			let token = deps
				.querier
				.keeta_token_address(env.contract.address.as_str(), &config.subdenom)?;
			let [coin] = info.funds.as_slice() else {
				return Err(StdError::generic_err("attach exactly one coin"));
			};
			if coin.denom != token {
				return Err(StdError::generic_err("can only return this faucet's token"));
			}
			Ok(Response::new()
				.add_message(KeetaMsg::Burn { subdenom: config.subdenom, amount: coin.amount.into() })
				.add_attribute("action", "return")
				.add_attribute("burned", coin.amount))
		}
	}
}

#[entry_point]
pub fn reply(deps: DepsMut<KeetaQuery>, _env: Env, msg: Reply) -> StdResult<KeetaResponse> {
	let mut stats = AIRDROP.load(deps.storage)?;
	match msg.result {
		SubMsgResult::Ok(_) => stats.succeeded += 1,
		SubMsgResult::Err(_) => stats.failed += 1,
	}
	AIRDROP.save(deps.storage, &stats)?;
	Ok(Response::new())
}

#[entry_point]
pub fn query(deps: Deps<KeetaQuery>, env: Env, msg: QueryMsg) -> StdResult<Binary> {
	let config = CONFIG.load(deps.storage)?;
	match msg {
		QueryMsg::Token {} => to_json_binary(
			&deps
				.querier
				.keeta_token_address(env.contract.address.as_str(), &config.subdenom)?,
		),
		QueryMsg::Supply {} => {
			let token = deps
				.querier
				.keeta_token_address(env.contract.address.as_str(), &config.subdenom)?;
			to_json_binary(&deps.querier.keeta_token_info(token)?.supply)
		}
		QueryMsg::AirdropStats {} => to_json_binary(&AIRDROP.load(deps.storage)?),
		QueryMsg::HasClaimed { address } => {
			let address = deps.api.addr_validate(&address)?;
			to_json_binary(&CLAIMED.has(deps.storage, &address))
		}
	}
}

fn mint(config: &Config, to: String) -> KeetaMsg {
	KeetaMsg::Mint { subdenom: config.subdenom.clone(), to, amount: config.claim_amount.into() }
}
