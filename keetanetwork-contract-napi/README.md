# @keetanetwork/contract-engine

Node.js bindings for `keetanetwork-contract-engine`, the sBPF contract
engine. A Keeta node runs each `CONTRACT_CALL` on its ledger with it.

```js
const { ContractEngine } = require('@keetanetwork/contract-engine');

const engine = new ContractEngine(
	JSON.stringify({ network: 0 }),
	async (request) => JSON.stringify(await answer(JSON.parse(request)))
);
await engine.storeCode(elf);
const call = {
	caller: 'keeta_…',
	instruction: {
		contract,
		accounts: [{ owner: contract, id: '<64 hex digits>', writable: true }],
		data: Buffer.from([0, 0]).toString('base64')
	},
	funds: [],
	gasLimit: '1400000',
	timeMillis: block.date.valueOf()
};
const outcome = JSON.parse(await engine.runLedgerCall(JSON.stringify(call)));
```

## How it fits together

- **The node owns all I/O.** The engine reads the ledger through one
  callback, `host(request: string) => Promise<string>`. Each call runs on
  its own thread and waits for each answer, while the event loop stays free
  to query the database. The callback is weak, so an idle engine does not
  keep the process alive.
- **Calls change nothing.** `runLedgerCall` resolves to what the call read,
  wrote and did, for the node to vote on and apply.
- **Engine failures are outcomes, not exceptions.** Calls resolve to
  `{"ok": …}` or `{"error": {"kind", "message"}}`. The `kind` is a stable
  name such as `contract`, `invalidAccount`, `outOfGas`, `ledger` or
  `host`. A promise only rejects for malformed input or a crashed call.

## API

- `new ContractEngine(config, host)`: `config` is
  `{ network, maxCallDepth?, maxCodeSize? }`.
- `storeCode(elf)` checks an sBPF v3 ELF file and keeps it loaded. It
  resolves to `{ checksum }`, the code's SHA-256 in hex.
- `runLedgerCall(call)` runs a contract call. `call` is
  `{ caller, instruction, funds?, gasLimit, timeMillis }`; `funds` are the
  `{ token, amount }` the caller's block sends the contract, which the
  block's own `SEND`s move.

Contracts follow Solana's model (see the engine's README). An instruction is

```json
{ "contract": "keeta_…",
  "accounts": [{ "owner": "keeta_…", "id": "<64 hex digits>", "writable": true }],
  "data": "<base64>" }
```

`accounts` lists every account the call touches, including those of
contracts it invokes. An account belongs to its `owner` contract and is
named by a 32-byte `id`, by convention the SHA-256 of its seeds
(`state_id(seeds)` in contracts). `data` is whatever the contract decodes
(the example contracts use borsh).

## Wire format

All JSON fields are camelCase. Byte strings are base64, hashes and account
ids are lowercase hex, and `u64` values are decimal strings (numbers are
accepted on input).

**Host requests** each have an `op` and expect the answers below:

| `op` | Fields | Answer |
| --- | --- | --- |
| `codeBytes` | `checksum` | base64 ELF or `null` |
| `contract` | `address` | `{ address, codeHash, info: { name, description, metadata } }` or `null` |
| `storageGet` | `contract`, `key` (an account id) | base64 account data or `null` |
| `balance` | `account`, `token` | decimal string |
| `tokenSupply` | `token` | decimal string, or `null` if the token does not exist |
| `sendRefusal` | `from`, `to`, `token` | why the ledger would refuse a `SEND` of `token` from `from` to `to` (a missing `ACCESS`, `STORAGE_CAN_HOLD` or `STORAGE_DEPOSIT`), or `null` if it would accept one. Asked before each `SEND` a contract makes; a refusal fails the call. |

**Outcomes** resolve to
`{ data, events, logs, gasUsed, reads, writes, effects }`:

- `reads` is every state account the call read, `{ owner, id, data }`,
  with the data it had; `writes` every account it changed, with its new
  data (`null` deletes it). Both are in `(owner, id)` order.
- `effects` are the contracts' `SEND`s, in order
  (`{ kind: 'send', from, to, token, amount, external }`), then a
  `{ kind: 'setInfo', account, name, description, metadata }` for each
  contract whose info changed.
- `events` has one entry per contract invocation, outermost first:
  `{ contract, attributes }`.

## Building and testing

```sh
npm install
npm run build        # release build for this platform
npm run build:debug
node --test __test__/engine.test.mjs
```

The tests use the example contracts in
`../keetanetwork-contract-engine/tests/contracts`, and build them if needed
with `cargo-build-sbf` from Anza's toolchain (`$CARGO_BUILD_SBF`, or the
installer's default location).

## Publishing

As with `@keetanetwork/asn1-napi-rs`, one package carries the prebuilt
binary for each target in `package.json` (`napi.targets`) and is published
to GitHub Packages. The generated `index.js` loads the right binary for the
platform.
