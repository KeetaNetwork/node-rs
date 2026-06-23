# keetanetwork-client-wasi

WASI bindings for the KeetaNet client in two feature-selected flavors over one
shared pure-logic core ([`src/pure.rs`](src/pure.rs)):

| Feature | Target | Artifact | Surface |
| ------- | ------ | -------- | ------- |
| `p2` | `wasm32-wasip2` | Component Model component | Networked client over `wstd`/`wasi:http` **plus** the pure/offline surface |
| `p1` | `wasm32-wasip1` | Core module | Pure/offline surface only, over a flat C ABI (networking is the host's job) |

Exactly one of `p1`/`p2` must be enabled for a wasi build (a `compile_error!`
enforces this). Off a wasi target the ABI modules compile out, so the workspace
host build and the `pure` unit tests stay green even under `--all-features`.

## Why two flavors

Standard WASI Preview 1 (what Rust's `wasm32-wasip1` std targets) has sockets
only over host-provided fds: `sock_accept`/`sock_recv`/`sock_send`, so Rust can
speak HTTP over an inherited or host-dialed connection. It has **no outbound
`connect`** in the standard (`TcpStream::connect`/`TcpListener::bind` return
`unsupported`); dialing out needs the host to connect and hand over the fd, or a
non-standard extension (WasmEdge/WASIX). First-class `wasi:sockets`/`wasi:http`
arrived in Preview 2. P1 is also what pure-JVM runtimes (Endive, Chicory) run
today.

So the outbound-networked surface is **P2 only** (via `wasi:http`); the
pure/offline surface is **shared**; and a P1 host (e.g. the JVM) does the
dialing — either performing HTTP itself, or connecting and letting the P1 module
speak HTTP over the socket. The P2 component is hosted by `wasmtime` (or JCO/JS)
until Component Model support lands in the JVM runtimes.

## Shared pure surface (`src/pure.rs`)

Target-agnostic, host-testable logic reused by both ABIs: account derivation
(seed/private/public/passphrase/address), identifiers, sign/verify/
encrypt/decrypt, permission sets, the offline `BlockBuilder` with operations
(`SET_REP`, `SET_INFO`, `MODIFY_PERMISSIONS`, `CREATE_IDENTIFIER` multisig),
build/sign/serialize, vote/staple projections, and X.509 `MANAGE_CERTIFICATE`.
It reuses `keetanetwork-bindings` so there is no logic duplication.

## P2 component (`src/p2/`, feature `p2`)

The exported world is defined in [`wit/world.wit`](wit/world.wit) (the
`keeta:client` package). It exposes a `node` resource (networked reads:
version, balances, token supply, account state, head/block lookup, vote staple,
representatives, ledger checksum, chain + chain-page, history, pending block,
head info) and a read-only `user-client` resource scoped to one operating
account. Outbound HTTP uses the `wasi:http/outgoing-handler` import, which the
host must grant.

```bash
rustup target add wasm32-wasip2
cargo build -p keetanetwork-client-wasi --target wasm32-wasip2 --features p2 --release
```

The `wasm32-wasip2` linker emits a component directly. Inspect the exported
world with [`wasm-tools`](https://github.com/bytecodealliance/wasm-tools):

```bash
wasm-tools component wit target/wasm32-wasip2/release/keetanetwork_client_wasi.wasm
```

Run it on any Component Model host. With `wasmtime`, grant outbound HTTP with
`-S http`; JavaScript hosts can transpile it with
[`jco`](https://github.com/bytecodealliance/jco).

## P1 core module (`src/p1/`, feature `p1`)

The pure/offline surface over a flat, handle-based C ABI modeled on the JNI
binding: opaque `i32` handles into
a registry, `keeta_alloc`/`keeta_dealloc` for guest memory, and
`(ptr, len)` byte transfers. Object-producing calls return a handle (`0` on
error, with the failure available via `keeta_last_error_code` /
`keeta_last_error_message`); variable-length results return a *bytes handle* the
host reads via `keeta_bytes_ptr`/`keeta_bytes_len` then frees with
`keeta_bytes_free`.

```bash
rustup target add wasm32-wasip1
cargo build -p keetanetwork-client-wasi --target wasm32-wasip1 --features p1 --release
```

## Tests

`pure` is covered by native unit tests (`cargo test -p keetanetwork-client-wasi`).
Two `wasmtime` host smoke tests exercise the built artifacts end to end:

- **P1 flat ABI** (`smoke.rs`): derive an account, then build and sign an opening
  block over the handle-based ABI, asserting deterministic hashes.
- **P2 networked** (`p2_net.rs`): boot a live reference node via the `E2eNode`
  harness, instantiate the component with `wasmtime-wasi` + `wasmtime-wasi-http`,
  and drive the exported `node`/`user-client` resources over `wasi:http`
  (version, balances, state, representatives, chain/history/head-info), proving the component runs against
  a real node — not just that it compiles.

They live in [`host-tests/`](host-tests) as their own workspace so `wasmtime`
never enters the default `cargo test`:

```bash
make test-wasi   # builds both artifacts + the node harness, then runs both smoke tests
```
