# Quickstart

## Abstract

This page is the install, build, test, and first-use path for the `node-rs` workspace. It records the Makefile targets from the repository Makefile. It also states the GitHub Packages gate and the cargo-only path.

## Purpose

Read this page when you clone the repository or when you need a correct Make command. After reading you can set up the toolchain and run a debug or release build. You can also choose a test path and start from an existing rustdoc example.

## Pin the toolchain

Use Rust `1.94.0` from `rust-toolchain.toml`. After you clone, that pin wins over a default rustup toolchain.

The file also requests `rustfmt`, `clippy`, and `llvm-tools-preview`. It also requests the `wasm32-unknown-unknown`, `wasm32-wasip1`, and `wasm32-wasip2` targets.

## Set up the tree

Run first-time setup.

```bash
make developer
```

`make developer` installs rustc through `scripts/rustup-init.sh -y --default-toolchain stable` when rustc is missing. That script requests the `stable` toolchain. The repo pin still selects `1.94.0` for this tree after clone.

## Build

Use the Make targets. Use `make build release=1` for a release build.

| Target | What you get |
| --- | --- |
| `make developer` | First-time toolchain and tool setup |
| `make build` | Debug build through `cargo build` |
| `make build release=1` | Release build through `cargo build --release` |
| `make check` | Compilation check through `cargo check` |

Release build:

```bash
make build release=1
```

`make release` runs `scripts/release.sh` and publishes crates to crates.io. That target is a publish path. It is not a release build.

## Test

`make test` depends on `make node-harness`. It then runs `cargo test --all-features --workspace`.

| Target | What you get |
| --- | --- |
| `make test` | Harness build, then workspace tests with all features |
| `make test-feat` | Feature matrix from the `Makefile` `test-feat` recipe |
| `make test-all` | `make test` and then `make test-feat` |

Those targets need the Packages gate below. Use the cargo-only path when you lack Packages read.

## Wasm and WASI

Name these targets when you need those ABIs. They also need the Packages gate. The Make targets are the first-use path for those ABIs.

| Target | What you get |
| --- | --- |
| `make build-wasm` | `wasm-pack build` for `keetanetwork-client-wasm` |
| `make test-wasm` | Harness, wasm-pack node tests, and Playwright in `keetanetwork-client-wasm/tests` |
| `make build-wasi` | WASI P1 and P2 debug artifacts for `keetanetwork-client-wasi` |
| `make test-wasi` | Harness, WASI artifacts, and host tests under `keetanetwork-client-wasi/host-tests` |

`make test-wasi` selects `p1` for `wasm32-wasip1` and `p2` for `wasm32-wasip2`. [Architecture](ARCHITECTURE.md) holds that one-feature contract.

## rustdoc

| Target | What you get |
| --- | --- |
| `make do-docs` | `cargo doc` for the workspace, then opens the result |
| `make do-docs-ci` | The same rustdoc build without opening a browser |

## GitHub Packages gate

`keetanetwork-utils/node-harness/.npmrc` sets `@keetanetwork:registry=https://npm.pkg.github.com`. The harness `package.json` depends on `@keetanetwork/keetanet-node` from that registry.

`make node-harness`, `make test`, `make test-all`, `make test-wasm`, and `make test-wasi` need read access to that package. CI sets `NODE_AUTH_TOKEN` for those jobs in `.github/workflows/ci.yml`.

Set `NODE_AUTH_TOKEN` or `GITHUB_TOKEN` to a GitHub personal access token with `read:packages`. Authorize SSO for the organization when the organization requires it.

Rust crates in this workspace use path dependencies. `.cargo/config.toml` sets a `wasm32-unknown-unknown` `getrandom` cfg. It does not set a private Cargo registry.

## Cargo-only path

Skip the harness when you do not have Packages read.

```bash
cargo check
cargo build
```

You can also run crate tests that do not enable the `node-harness` feature. `make test` still needs the harness and auth.

## First use

Start from the rustdoc examples that already live in the crates. This tree does not add an `examples/` directory.

Construct a `KeetaClient` against the local API from [`keetanetwork-client/src/lib.rs`](https://github.com/KeetaNetwork/node-rs/blob/285ce02435bbcc120e86a7c78d2865a034679453/keetanetwork-client/src/lib.rs#L11-L37).

```rust
let client = KeetaClient::new("http://localhost:8080/api").with_network(0u8);
```

`UserClient` signing tests live in [`keetanetwork-client/tests/user_signing.rs`](https://github.com/KeetaNetwork/node-rs/blob/285ce02435bbcc120e86a7c78d2865a034679453/keetanetwork-client/tests/user_signing.rs#L8-L20). A live harness cookbook lives in [`keetanetwork-client/tests/e2e.rs`](https://github.com/KeetaNetwork/node-rs/blob/285ce02435bbcc120e86a7c78d2865a034679453/keetanetwork-client/tests/e2e.rs#L164).

Build a signed opening block from [`keetanetwork-block/src/lib.rs`](https://github.com/KeetaNetwork/node-rs/blob/285ce02435bbcc120e86a7c78d2865a034679453/keetanetwork-block/src/lib.rs#L8-L39).

```rust
let unsigned = BlockBuilder::default()
	.with_network(0u8)
	.with_account(account.clone())
	.as_opening()
	.build()?;
let block = unsigned.sign()?;
```

A harness opening-block cookbook lives in [`keetanetwork-block/tests/e2e.rs`](https://github.com/KeetaNetwork/node-rs/blob/285ce02435bbcc120e86a7c78d2865a034679453/keetanetwork-block/tests/e2e.rs#L116-L119).

## Falsified by

A change to the `developer`, `build`, `check`, `test`, `test-feat`, `test-all`, `build-wasm`, `test-wasm`, `build-wasi`, `test-wasi`, `do-docs`, `do-docs-ci`, or `release` targets in `Makefile`. A change to the channel in `rust-toolchain.toml`. A change to the registry line in `keetanetwork-utils/node-harness/.npmrc`. A change to the `KeetaClient` or `BlockBuilder` rustdoc examples in those crate `lib.rs` files.
