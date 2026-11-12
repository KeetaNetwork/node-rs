# keetanetwork-contract-std

This crate is the SDK for Keeta smart contracts written in Rust. It also holds the binary interface (`abi`) that every contract shares with `keetanetwork-contract-engine`, whatever language the contract is written in. Contracts are sBPF v3 programs that follow Solana's account model. The engine's [README](../../keetanetwork-contract-engine/README.md) is the home for that model, the host functions, and how a call runs.

## Quickstart

The crate has no default features. Feature `borsh` adds `BorshSerialize` and `BorshDeserialize` for `Address`, typed `Account::load` and `Account::store`, and, on off-chain builds, the `interface` module. Contracts usually turn it on.

```bash
cargo test -p keetanetwork-contract-std
```

The engine's tests build the example contracts in `keetanetwork-contract-engine/tests/contracts` and run them end to end.

```bash
cargo test -p keetanetwork-contract-engine
```

## Set up a contract crate

1. Install Anza's toolchain. It provides `cargo-build-sbf` and, on first use, downloads Solana's platform tools (a Rust and LLVM fork).

   ```bash
   sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
   ```

2. Put the contract in a Cargo workspace of its own. The contract builds only for the `sbpfv3-solana-solana` target, with the platform tools' Rust, and not with this repository's toolchain. `keetanetwork-contract-engine/tests/contracts/Cargo.toml` is the model. When host tests also use the contract as a path dependency, spell out its package fields instead of inheriting them from the workspace.

3. Declare the crate as a `cdylib` for the program and an `rlib` so that host tests and clients can use its types and account-naming helpers. Turn off borsh's default `std` feature, and gate its schema feature to off-chain builds, so the on-chain program does not change.

4. Set the release profile in the workspace root. `overflow-checks = true` turns arithmetic overflow into a panic, which fails the call, instead of a silent wrap.

5. Write a `process` function and declare it with `entrypoint!`. The macro also installs the heap allocator and reports panics as the contract's error.

6. Build with `cargo build-sbf --arch v3` (in a workspace, one contract at a time, with `--manifest-path`; see "Call another contract"). The program lands in `target/deploy/<crate_name>.so`. The engine refuses code built for any other sBPF version when it is stored.

### Cargo manifest

From `keetanetwork-contract-engine/tests/contracts/keeta-pet/Cargo.toml`.

```toml
[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
# borsh's `std` would bring Rust's formatting code into the contract (see keetanetwork-contract-std).
borsh = { version = "1", default-features = false, features = ["derive"] }
keetanetwork-contract-std = { path = "../../../../keetanetwork-contract-std", features = ["borsh"] }

# Off-chain, borsh's schemas, for `contract_interface`. On-chain builds do not change.
[target.'cfg(not(target_os = "solana"))'.dependencies]
borsh = { version = "1", features = ["derive", "unstable__schema"] }

[lints.rust]
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(target_os, values("solana"))'] }
```

### Release profile

From `keetanetwork-contract-engine/tests/contracts/Cargo.toml`.

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
overflow-checks = true
```

## Write the entrypoint

The entrypoint receives a `Context` with the caller, the contract's own address, the block time, the funds attached, the accounts the instruction lists, and the raw instruction data. Return `Ok(())` to commit the call. Return an error, or panic, to undo the whole call.

### Counter

From `keetanetwork-contract-std/src/lib.rs` crate rustdoc.

```rust
use keetanetwork_contract_std::{entrypoint, Context, ContractResult};

entrypoint!(process);

fn process(ctx: &mut Context) -> ContractResult {
	let counter = ctx.account(0)?;
	let next = counter.load::<u64>()?.unwrap_or_default() + 1;
	counter.store(&next)
}
```

## Define instructions and accounts

Instruction data is raw bytes. The example contracts decode a borsh `enum`, one variant per action, and document which accounts each variant expects in which order. Name each state account with `state_id` over fixed seeds, and export one helper per account kind. Clients and tests then compute the same ids, because `state_id` runs off-chain too. The Node.js bindings compute them with `stateIdOf`.

Fetch accounts with `Context::own_account`, which checks the owner and id, rather than trusting the position alone. The engine enforces who may change which account whatever the SDK checks, so a check in the contract is about naming the right account, not about permissions.

### Instructions and account ids

From `keetanetwork-contract-engine/tests/contracts/keeta-pet/src/lib.rs`.

```rust
#[derive(BorshSerialize, BorshDeserialize, Debug)]
#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]
pub enum Instruction {
	/// Accounts: config (writable). Set the meal price; the caller becomes
	/// the admin. Only once.
	Init { food_token: Address, food_price: u128 },
	/// Accounts: config, the caller's pet (writable). Allowed when you have
	/// no pet, or yours ran away.
	Adopt { name: String },
	/// Accounts: config, the caller's pet (writable). Attach exactly the
	/// meal price.
	Feed,
	/// Accounts: config, the caller's pet (writable).
	Play,
	/// Accounts: config. Admin only: send the food money to `to`.
	Withdraw { to: Address },
	/// Accounts: config, then any pet accounts. Returns `Vec<PetView>`.
	Pets,
}

/// The config account's id.
pub fn config_id() -> StateId {
	state_id(&[b"config"])
}

/// The id of `owner`'s pet account.
pub fn pet_id(owner: &Address) -> StateId {
	state_id(&[b"pet", &owner.0])
}
```

### One-time setup

From `keetanetwork-contract-engine/tests/contracts/keeta-pet/src/lib.rs` `process`. Deploying runs no code, so a contract sets itself up in an instruction of its own. Refuse a second `Init` by checking that the config account is still empty.

```rust
	if let Instruction::Init { food_token, food_price } = instruction {
		ctx.no_funds()?;
		ensure!(food_price > 0, "food_price must not be zero");
		let caller = ctx.caller;
		let config = ctx.own_account(0, &config_id())?;
		ensure!(config.is_empty(), "already initialized");
		config.store(&Config { admin: caller, food_token, food_price })?;
		set_info("KEETA_PET", "A virtual pet contract", "");
		attribute("action", "init");
		return Ok(());
	}
```

Whoever sends `Init` first becomes the admin. Deploy and initialize back to back, or check the caller against an address built into the contract.

## Call another contract

A contract calls another with `invoke`, passing on accounts from its own call: the caller lists the callee's state
accounts in its instruction, and `invoke` names them by index. What the callee returns with `set_return_data`, the
caller reads with `return_data`. If the callee fails, the whole call fails. To pay a contract, `send` to it first: the
callee sees the payment in its `balance`, as funds are not passed with `invoke`.

To use the callee's instruction and account types, depend on its crate with a `no-entrypoint` feature that leaves out
its entrypoint (Solana's convention), as `keeta-pet` does with `keeta-pet-shop`:

```toml
# keeta-pet-shop/Cargo.toml
[features]
no-entrypoint = []

# keeta-pet/Cargo.toml
[dependencies]
keeta-pet-shop = { path = "../keeta-pet-shop", features = ["no-entrypoint"] }
```

```rust
// keeta-pet-shop: #[cfg(not(feature = "no-entrypoint"))] entrypoint!(process);
// keeta-pet, feeding: the shop's account is the call's third
send(&config.shop, &fund.token, fund.amount, Some("keeta pet meal"));
invoke(&config.shop, &[(2, true)], &borsh::to_vec(&ShopInstruction::Buy { quantity: 1 })?);
let receipt = Receipt::try_from_slice(&return_data())?;
```

Build such contracts one at a time (`cargo build-sbf --arch v3 --manifest-path <contract>/Cargo.toml`): a build of the
whole workspace unifies features, and would build the callee with `no-entrypoint` too. The ledger also needs an
ordering on the callee's chain, from the same sequencer, in the staple of any call that lists the callee's state; the
contract sequencer adds it.

## Rules for contract code

| Rule | Why |
| --- | --- |
| Keep no writable statics, such as `static mut` or a `static` with interior mutability. | sBPF programs have no writable data section. The target's linker script discards `.data` and `.bss`, so the link fails. Keep state in accounts. |
| Allocate within the 256 KiB heap (`HEAP_SIZE` in `src/abi.rs`). | `BumpAllocator` never frees. An invocation is short, so the heap only has to last one call. |
| Treat every host function as returning only on success. | A failing `send`, `invoke` or other host function aborts the whole call, so there is no error to handle. |
| Derive behavior from `Context` and account data only. | Every node that runs the call must reach the same result. `Context::time_millis` is the only clock, and there is no randomness. |
| Return computed results with `set_return_data`. | Return data is part of a call's outcome. Clients run such an instruction as a simulation (`simulateContractCall` in the node's client), which keeps nothing, for anything derived, such as the pet's mood at the block time. |
| Build messages from pieces, not with `format!`: `bail!("attach exactly ", price, " of the token")`, `attribute("fullness", value)`, `log(&text!("fed ", meals, " times"))`. | Every deploy pays by the byte, and Rust's formatting code (`format!`, `Display`, `{:?}`) is about 30 KB of a contract. The SDK's `text` module joins strings and integers without it, and the engine writes the numbers (`keeta_decimal`). `bail!` refuses a message with `{`. A panic reports its message only when it is plain text. |
| Avoid `std` features that format, such as borsh's `std` and `.to_string()` on errors. | They bring the formatting code back even when nothing is printed: a boxed `std::io::Error` keeps its `Debug` and `Display` code. |
| Gate off-chain code with `cfg(not(target_os = "solana"))`. | Host builds compile the contract for tests and clients. Host functions panic there, while `sha256` and `state_id` compute locally. |

The limits on accounts, instruction data, return data, log text and account growth are constants in `keetanetwork-contract-std/src/abi.rs`.

## Test a contract

Test pure logic with a host build of the contract crate (`cargo test` in the contract's workspace). Test the program itself with `Engine` and `MemoryHost`, the way `keetanetwork-contract-engine/tests/contracts.rs` does.

1. Build the program with `cargo build-sbf --arch v3`.
2. Check the ELF with `Engine::store_code`, and deploy it at an address with `MemoryHost::deploy`.
3. Run each call with `Engine::run_ledger_call`, and apply each successful outcome with `MemoryHost::apply`.

`MemoryHost::apply` applies an outcome as the ledger does, so the test also checks that no balance goes negative and that every `SEND` passes the ledger's permissions. The test `a_pet_lives_in_its_owners_account` in `keetanetwork-contract-engine/tests/contracts.rs` is a complete example.

## Describe the interface

Write a `contract_interface` function so that explorers and other tools can decode the contract's instruction data, state accounts and views. It builds on borsh schemas and exists only off-chain, so the program does not change. The `keeta-contract interface --package <name>` command in anchor-contracts prints it as JSON in the `keeta-contract-interface` format that `src/interface.rs` documents.

### Interface

From `keetanetwork-contract-engine/tests/contracts/keeta-pet/src/lib.rs`.

```rust
#[cfg(not(target_os = "solana"))]
pub fn contract_interface() -> keetanetwork_contract_std::interface::Interface {
	use keetanetwork_contract_std::interface::{Interface, Seed};
	Interface::new("keeta-pet")
		.instruction::<Instruction>()
		.account::<Config>("config", &[Seed::bytes(b"config")])
		.account::<Pet>("pet", &[Seed::bytes(b"pet"), Seed::address("owner")])
		.view::<Vec<PetView>>("Pets")
}
```

## Deploy and call

The `keeta-contract` command in anchor-contracts (`src/services/contracts/cli.ts`) builds, deploys, calls and reads contracts. It reads the account from `KEETA_SEED` and the network from `KEETA_NETWORK`.

| Step | Command |
| --- | --- |
| Build | `keeta-contract build --package <name>` |
| Build so that others can check the source | `keeta-contract build --verifiable --package <name>` |
| Deploy | `keeta-contract deploy target/deploy/<crate_name>.so --admin <account>` |
| Call | `keeta-contract call '<instruction-json>' --funds <token>=<amount>` |
| Read state | `keeta-contract account <contract> <id-hex>` |
| Check deployed code against source | `keeta-contract verify <contract> --package <name> --source <dir>` |

Deploy the verifiable build when others should be able to check the contract's source against its code hash.

## Other languages

Any toolchain that emits an sBPF v3 ELF in the expected shape can produce a contract. [Contracts in other languages](../../docs/concepts/CONTRACTS-IN-OTHER-LANGUAGES.md) covers C and assembly.

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Contracts in other languages](../../docs/concepts/CONTRACTS-IN-OTHER-LANGUAGES.md)
- [Contract engine](../../keetanetwork-contract-engine/README.md) for the account model, the host functions and how a call runs
- [Workspace overview](../../docs/README.md)
