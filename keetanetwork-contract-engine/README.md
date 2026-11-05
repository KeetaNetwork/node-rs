# keetanetwork-contract-engine (Phase 0 spike)

A CosmWasm-compatible smart contract engine for Keeta. It runs Wasm
contracts on an in-memory Keeta ledger and turns each committed call into
the Keeta blocks a contract sequencer (anchor) would publish as one vote
staple.

This is a feasibility spike, not production code. It answers one question:
can we take the CosmWasm VM and toolchain as they are, run them on Keeta's
account and block model, and still get valid Keeta blocks out? The answer
is yes, with the caveats below.

## Layout

| Path | What it is |
| --- | --- |
| `../keetanetwork-contract-std` | Types contracts depend on: `KeetaMsg` (send with memo, `SET_INFO`, create/mint/burn native tokens) and `KeetaQuery` (account info, token address, token info). |
| `src/engine.rs` | Stores code, runs calls, dispatches messages (bank, wasm, Keeta), handles submessages/replies, rolls back on failure. |
| `src/backend.rs` | The VM backend: per-contract storage and the querier. |
| `src/state.rs` | In-memory ledger plus contract state, the operation journal and the state root. |
| `src/output.rs` | Turns the journal into `keetanetwork-block` unsigned blocks. Building a block runs Keeta's validation. |
| `tests/contracts/` | Example contracts in a separate wasm32 workspace: unmodified `cw20-base`, `keeta-escrow` and `keeta-faucet`. |

## Running

```sh
cargo test -p keetanetwork-contract-engine
```

The tests build `tests/contracts/` on first use with a plain
`cargo build --release --target wasm32-unknown-unknown`. The target is listed
in `rust-toolchain.toml`.

## What the tests show

| Claim | Test |
| --- | --- |
| Unmodified ecosystem contracts run | `unmodified_cw20_base_runs` |
| Contracts declare that they need Keeta extensions, and hosts without them refuse to load them | `contracts_declare_the_keeta_capability`, `hosts_without_keeta_extensions_refuse_keeta_contracts` |
| Contracts move native Keeta tokens, with `external` memos | `escrow_releases_native_tokens_with_a_memo`, `escrow_refunds_only_after_expiry` |
| Contracts call each other in one atomic call | `escrow_holds_cw20_and_releases_it_across_contracts` |
| A failure anywhere rolls back every contract | `a_failure_deep_in_a_call_rolls_back_every_contract` |
| Contracts issue, mint and burn native Keeta tokens | `faucet_issues_a_native_keeta_token` |
| Submessages and replies work, and a failed submessage leaves no trace | `airdrop_tolerates_bad_recipients_through_replies` |
| Keeta's field rules apply to what contracts output | `keeta_field_rules_apply_to_contract_output` |
| Gas is metered, and running out rolls back | `running_out_of_gas_aborts_and_rolls_back` |
| Same calls on the same state give the same state roots, block hashes and gas | `execution_is_deterministic` |

## Findings for Phase 1

1. **Toolchain and VM version.** node-rs is on Rust 1.96. The engine uses
   `cosmwasm-vm` **3.1.0-rc.1**, pinned exactly; move to 3.1.0 when it is
   released. 3.1 is the first VM to accept bulk-memory instructions.

2. **Contract builds: one ecosystem issue left.**
   - **Bulk memory (fixed by 3.1).** Since Rust 1.87, the prebuilt `std`
     for `wasm32-unknown-unknown` contains `memory.copy` and `memory.fill`.
     CosmWasm 3.0 rejects them ([CosmWasm/cosmwasm#2485]); 3.1 accepts them
     and charges gas according to the size of each copy or fill. On 3.0 the
     only ways around this were rebuilding `std` with nightly flags, or
     pinning Rust 1.86 the way `cosmwasm/optimizer` 0.17.0 does. Neither is
     needed now. Chains still on CosmWasm 3.0 will reject contracts built
     this way, but that does not matter for Keeta, which runs its own VM.
   - **Undefined imports.** Rust 1.96 stopped linking wasm with
     `--allow-undefined`. `cosmwasm-std` 2.x and 3.0 declare their host
     functions without `#[link(wasm_import_module = "env")]`, so contracts
     must link with `-C link-arg=--allow-undefined`
     (`tests/contracts/.cargo/config.toml`) until `cosmwasm-std` adds the
     attribute.

   A `keeta-contract build` command should apply that flag, so contract
   developers never see it.

[CosmWasm/cosmwasm#2485]: https://github.com/CosmWasm/cosmwasm/issues/2485

3. **Identifier addresses depend on the sequencer's chain head.** Keeta
   derives an identifier from the creating account's previous block hash and
   the operation's index in that block, and block validation enforces it.
   The engine puts all of a call's `CREATE_IDENTIFIER`s into one sequencer
   block at the start of the staple. That way, contract and token addresses
   are known while contracts run. Consequences:
   - The sequencer's own chain is a serialization point. It must not publish
     anything else between executing a call and publishing that call's
     staple, or the addresses become invalid.
   - A token's address can't be known before the token exists. So
     `KeetaQuery::TokenAddress` is a registry lookup, not a derivation.

4. **Who signs.** Contract and token accounts are identifiers owned by the
   sequencer, which signs their blocks. A user's funding leg is a block
   signed by the user. Today the engine builds that block itself. In Phase 1
   the wallet pre-signs it against its own chain head, and the sequencer
   must check it matches the call's `funds`.

5. **Some calls leave no on-chain trace.** A cw20 transfer only changes
   contract storage, so it produces no Keeta blocks. Phase 1 needs the
   per-call state commitment (`{codeHash, stateRoot, sequence}` in the
   contract account's metadata) for those calls to be auditable.

6. **Spike-only shortcuts to replace:**
   - The state root is a flat hash; replace it with a Merkle tree.
   - Rollback clones the whole state at each checkpoint; replace it with a
     journaled overlay.
   - The gas schedule for storage, queries and address operations is a
     placeholder.
   - `Reply.gas_used` is always 0.
   - Code is stored in a temporary cache directory.

7. **Not implemented:**
   - `migrate`, `sudo`, `Instantiate2`, IBC, staking/distribution, `Any`
     messages, denom metadata, `BankMsg::Burn`.
   - Signing and publishing blocks.
   - Fees.

   `CAPABILITIES` advertises the `cosmwasm_1_1`–`cosmwasm_2_2` versions
   because cw-plus contracts require them; the unimplemented features behind
   them fail at runtime. Phase 1 should either implement them or stop
   advertising them.

8. **Lockfile.** The new dependencies force semver-compatible bumps for the
   whole workspace: `cfg-if` 1.0.5, `libc` 0.2.191, `once_cell` 1.21.4 and
   `rayon` 1.12 (`rayon-core` 1.13). Every other change is an addition. Also,
   `cosmwasm-crypto` 3.1-rc and 2.3 need incompatible `ed25519-zebra`
   versions, so the workspace resolves the host-side copy of
   `contract-std`'s optional `cosmwasm-std` 2.x to 2.2.2. That copy is only
   built for `--all-features` lint and docs; the contracts have their own
   lockfile and use 2.3.6.
