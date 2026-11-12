# keetanetwork-contract-engine

An sBPF smart contract engine for Keeta. Representatives run each
`CONTRACT_CALL` on the ledger with it, and vote on the outcome: the state
the call read and wrote, and its ledger effects.

Contracts are sBPF v3 programs, the instruction set Solana runs, built with
Solana's platform tools and run in [`solana-sbpf`]'s interpreter. They follow
Solana's model: one entrypoint, raw instruction data, and state in accounts
that each instruction declares.

The engine holds no state between calls and changes nothing itself. It reads
the ledger (contracts, their code and state accounts, balances, token supply
and permissions) through the `Host` trait, and returns a `LedgerOutcome` for
the representative to vote on and apply.

[`solana-sbpf`]: https://github.com/anza-xyz/sbpf

## Layout

| Path | What it is |
| --- | --- |
| `../keetanetwork-contract-std` | The contract SDK (entrypoint, accounts, host functions) and the binary interface (`abi`) contracts share with the engine. |
| `src/engine.rs` | The public API: `Engine::store_code` and `Engine::run_ledger_call`, and the types of a call and its outcome. |
| `src/host.rs` | The `Host` trait: the ledger reads a call needs. |
| `src/vm.rs` | Running contracts: loading and verifying code, laying out a contract's input, the VM, every host function, and contracts invoking each other. |
| `src/overlay.rs` | A call's view of state: cached host reads with the call's writes on top. |
| `src/gas.rs` | Gas in compute units. |
| `src/memory.rs` | `MemoryHost`: a ledger in memory, for tests. |
| `tests/contracts/` | Example contracts in a separate sBPF workspace: `keeta-pet` and `keeta-pet-shop` (the contracts behind the web wallet's `examples/keeta-pet` dApp), `keeta-escrow`, and `keeta-probe`, which tests the engine's rules. |

## Running

```sh
cargo test -p keetanetwork-contract-engine
```

The tests build `tests/contracts/` on first use with
`cargo-build-sbf --arch v3`, from Anza's toolchain:

```sh
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
```

They find `cargo-build-sbf` through `$CARGO_BUILD_SBF`, on the `PATH`, or
where the installer puts it (`~/.local/share/solana/install/active_release/bin`).
The first build downloads Solana's platform tools (a Rust and LLVM fork).
The tests also build the contracts for the host, to use their instruction
and state types.

## Writing a contract

```rust
use keetanetwork_contract_std::{entrypoint, Context, ContractResult};

entrypoint!(process);

fn process(ctx: &mut Context) -> ContractResult {
	let counter = ctx.account(0)?;
	let next = counter.load::<u64>()?.unwrap_or_default() + 1;
	counter.store(&next)
}
```

A contract crate is a `cdylib` that depends on `keetanetwork-contract-std`
(usually with its `borsh` feature) and builds with `cargo build-sbf --arch v3`.
`entrypoint!` also installs the heap allocator and reports panics as contract
errors. The `Context` gives the caller, the contract's own address, the
block time, the funds attached, the accounts and the instruction data.

## The account model

- **An instruction** names a contract, lists accounts, and carries raw
  data. Each account is `(owner, id, writable)`: a piece of the `owner`
  contract's state, named by a 32-byte id (by convention `state_id(seeds)`,
  the SHA-256 of the seeds). The list must cover every account the call
  touches, including those of contracts it invokes, and may not repeat one.
- **Account data is mapped into the contract's memory.** A contract can read
  every account it is given, and change the data (and length, up to 10 KiB
  more per invocation and 1 MiB in all) of accounts that are both writable
  and its own. When the contract returns, the engine checks that everything
  else is unchanged, so the SDK's checks are a convenience, not the
  enforcement. An account with no data does not exist; emptying one
  deletes it.
- **Contracts invoke each other** with `invoke`, passing on some of their
  accounts. A writable account must be writable in the caller too. The
  callee sees the invoking contract as its caller, receives no funds (the
  caller can `send` first), and can return data. The engine writes the
  caller's changes to the call's state before the callee runs and refreshes
  the caller's copy afterwards, so both see the same data. At most
  `max_call_depth` (5) contracts run at once, and none can be re-entered.
- **Everything is atomic.** If any contract fails, panics or runs out of
  gas, or any host function fails (a `SEND` the contract cannot afford or
  the ledger's permissions refuse, a bad address), the whole call fails and
  has no outcome. A contract cannot catch a callee's failure.
- **Deploying runs no code.** A contract sets itself up in an instruction
  of its own (the example contracts' `Init`, which makes its caller the
  admin).

## Host functions

Contracts reach the ledger through host functions (`keetanetwork-contract-std`
wraps each). Ledger effects run as the contract's own Keeta account, which
also holds the funds callers attach. A contract can move only what that
account holds: it cannot spend a caller's other tokens, which callers attach
as funds instead.

Every `SEND` a contract makes follows Keeta's permissions, as a signed `SEND`
would: `ACCESS` on the token for both accounts and, into a storage account,
`STORAGE_CAN_HOLD` and `STORAGE_DEPOSIT`. The engine asks the host
(`Host::send_refusal`), so a token's admin can keep a contract from paying an
account it has not approved, and a refusal fails the call.

| Function | Does |
| --- | --- |
| `send` | `SEND` from the contract, with an optional `external` memo |
| `balance`, `supply` | An account's balance of a token, and a token's supply |
| `set_info` | `SET_INFO` on the contract, held to Keeta's field rules |
| `invoke`, `set_return_data`, `return_data` | Call another contract and pass data back |
| `log`, `attribute` | Log lines, and attributes on the invocation's event |
| `sha256`, `state_id` | Hashing, and naming accounts |
| `keeta_decimal` (the SDK's `text!`, `bail!`, `attribute`) | An integer in decimal, written into the contract's memory, so contracts carry no number-printing code |

The SDK also provides `memcpy`, `memmove`, `memset` and `memcmp`, which
call `keeta_memcpy` and the rest, in place of the platform toolchain's
compiler builtins. The only other host functions are the two the
toolchain's own `std` calls: `abort` and `sol_log_`. Code that calls
anything else is refused when it is stored, so a contract must be built
with the SDK. The SDK's panic handler reports a panic's message with
`keeta_error` and then calls `keeta_panic` with where it happened, and the engine writes
`panicked at <file>:<line>:<column>: <message>`: contracts carry no code to
format panics.

## How a call works

1. **The call.** A `LedgerCall` is what the caller's block carries: the
   caller, the instruction, the funds the block sends the contract, the gas
   limit and the block's time. The block's own `SEND`s move the funds; the
   engine credits them to the contract for the call, so the contract sees
   them in its balance and its `funds`.
2. **Gas.** Gas is in compute units, as on Solana: one per sBPF instruction,
   plus a charge for each host function, each invocation, loading accounts
   and writing them back (`src/gas.rs`). The node turns the gas used into
   fee units.
3. **Execution.** The instruction runs as described above, against the
   host's state with the call's own writes on top.
4. **Outcome.** `LedgerOutcome` lists every state account the call read
   (with the data it had), every account it changed (with its new data),
   and its effects: the contracts' `SEND`s in order, then a `SET_INFO` for
   each contract whose info changed. It also carries the return data,
   events, logs and gas used.

## What the tests show

| Claim | Test |
| --- | --- |
| A pet's state lives in its owner's account, decays with block time, and only its owner can reach it | `a_pet_lives_in_its_owners_account`, `a_starved_pet_runs_away` |
| A pet buys its meals from the shop, paying with the funds its caller attached | `a_pet_buys_its_meals_from_the_shop` |
| A contract's `SEND`s need the same permissions as a signed `SEND` | `contract_sends_follow_the_ledgers_permissions` |
| Contracts move native tokens, with `external` memos | `escrow_releases_native_tokens_with_a_memo`, `escrow_refunds_only_after_expiry` |
| A contract sees its caller, the block time, its funds and its accounts | `a_contract_sees_its_caller_the_time_its_funds_and_its_accounts` |
| A call reports what it read and wrote, and its effects | `a_call_reports_what_it_read_and_wrote` |
| The engine, not the SDK, enforces who may change which account | `contracts_change_only_their_own_writable_accounts` |
| Contracts invoke each other and share accounts, without gaining privileges | `contracts_invoke_each_other_and_share_accounts` |
| No re-entry, and a depth limit | `contracts_cannot_be_reentered_or_nested_too_deeply` |
| Panics, errors and endless loops fail the call | `panics_errors_and_endless_loops_fail_the_call` |
| A failure anywhere fails the whole call | `a_failure_anywhere_fails_the_whole_call` |
| Contracts set their account's info within Keeta's field rules, and setting the same info is no effect | `contracts_set_their_accounts_info_within_keetas_field_rules` |
| Contracts cannot overspend | `contracts_cannot_overspend` |
| Only sBPF v3 code is stored | `only_sbpf_v3_contracts_are_stored` |
| Code is capped in size when stored (512 KiB by default, as on the node), and code already deployed keeps running if the cap is lowered | `code_size_is_capped_when_stored` |
| Host failures abort the call | `host_failures_abort_the_call` |
| Code is reloaded from the host after a restart | `a_restarted_engine_reloads_code_from_the_host` |
| Same calls on the same state give the same outcome and gas | `execution_is_deterministic` |

Every successful call is applied through `MemoryHost::apply`, as the ledger
applies an accepted call. So the tests also check that no outcome overdraws
an account or sends where the ledger's permissions refuse.

## Notes

1. **Toolchains.** The engine builds with the workspace's Rust (1.96).
   Contracts build with Anza's platform tools (`cargo build-sbf --arch v3`;
   tested with `cargo-build-sbf` 4.4.0, platform tools v1.57), which bring
   their own Rust. The engine only accepts sBPF v3.

2. **sBPF programs cannot have writable statics.** The SDK's allocator keeps
   its position in the heap for that reason; contract code must not use
   `static mut` or other writable globals either. The linker refuses them.

3. **Contract accounts accept tokens.** On Keeta, a `SEND` into a storage
   account needs two grants from that account: `STORAGE_CAN_HOLD` for the
   token and `STORAGE_DEPOSIT` for the sender. The node gives every contract
   account both as its default permissions when it is deployed.
   `MemoryHost` does the same, enforces the storage rule, and
   `MemoryHost::set_access` takes an account's `ACCESS` on a token away.

4. **Contracts cannot issue tokens.** Keeta requires every token to have a
   key-holding owner, so there are no host functions to create, mint or
   burn them.

5. **Initialization is first come, first served.** Deploying runs no code,
   so whoever sends a contract's `Init` first becomes its admin in the
   example contracts. Deploy and initialize back to back, or have the
   contract check its caller against an address built into it.

6. **Gas costs for storage and ledger operations are provisional.** Solana
   prices those through rent and fees, which have no equivalent here.

7. **Not implemented:** funds on contract-to-contract invocations (send,
   then invoke), and the JIT (x86-64 only in `solana-sbpf`; every host uses
   the interpreter).
