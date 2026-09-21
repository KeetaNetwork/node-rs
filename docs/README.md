# Overview

## Abstract

This guide is the cultural map for the `node-rs` workspace. Invariant detail lives on [Architecture](ARCHITECTURE.md) and the crate notes. Install, build, and test steps live on [Quickstart](QUICKSTART.md).

## Purpose

An engineer reads this guide in the first week on the workspace. After reading, the engineer can name the page that holds each inbound question. The engineer can also find the living documentation map.

| Next question | The page |
| --- | --- |
| How do the crates depend on and call each other? | [Architecture](ARCHITECTURE.md) |
| How does a reader install, build, and test? | [Quickstart](QUICKSTART.md) |
| How does a writer review a page in this tree? | [Documentation Standard](STANDARD.md) |
| Where do account identities live? | [Account](crates/account.md) |
| Where do shared errors live? | [Error](crates/error.md) |
| Where do signing primitives live? | [Crypto](crates/crypto.md) |
| Where do certificate builders live? | [X.509](crates/x509.md) |
| Where does the ASN.1 codec contract live? | [ASN.1](crates/asn1.md) |
| Where do test helpers and the harness live? | [Utils](crates/utils.md) |
| Where do opening-hash and block signing live? | [Block](crates/block.md) |
| Where do vote, quote, and staple live? | [Vote](crates/vote.md) |
| Where do `KeetaClient` and HTTP generation live? | [Client](crates/client.md) |
| Where does the shared host projection live? | [Bindings](crates/bindings.md) |
| Where does the browser ABI live? | [Client wasm](crates/client-wasm.md) |
| Where does the WASI `p1` / `p2` contract live? | [Client WASI](crates/client-wasi.md) |

## What this workspace is

This repository is a Cargo workspace of Keeta Network node crates. Root `Cargo.toml` `[workspace].members` is the member list. Crate identity lives in each member `Cargo.toml` `description` plus rustdoc on that crate `lib.rs`.

Each product crate listed on this guide has one note under `docs/crates/`. `keetanetwork-node` and `keetanetwork-ledger` are empty stubs. Those crates do not hold product types. [Architecture](ARCHITECTURE.md) names that boundary.

Each member crate carries its own version in that crate `Cargo.toml`. This guide does not treat the unused workspace package version as the repository version. This table of contents does not stamp versions.

The files state three license strings. Root `LICENSE` is the Keeta Token Network Community License (v1.0). Workspace `Cargo.toml` `license` is `MIT`. `keetanetwork-utils/node-harness/package.json` `license` is `Keeta Token Network Community License`. This guide cites those files as written.

## How the pieces fit together

Make owns the build. The [package README](../README.md) and the `Makefile` drive setup, build, check, test, and publish. [Quickstart](QUICKSTART.md) holds the commands.

Crate rustdoc is the API reference. `make do-docs` generates it. This tree does not copy export lists.

[Architecture](ARCHITECTURE.md) holds the collaboration graph and the signed-write path. Each crate note holds that crate's consumer contract. A `docs/concepts/` page lands only when it still holds a non-rustdoc invariant that Architecture and the crate notes do not already carry.

## Crate notes

These pages are the living table of contents for product crates. [Architecture](ARCHITECTURE.md) draws the graph. Each note names the crates that call that crate.

| Crate | Note |
| --- | --- |
| `keetanetwork-account` | [Account](crates/account.md) |
| `keetanetwork-error` | [Error](crates/error.md) |
| `keetanetwork-crypto` | [Crypto](crates/crypto.md) |
| `keetanetwork-x509` | [X.509](crates/x509.md) |
| `keetanetwork-asn1` | [ASN.1](crates/asn1.md) |
| `keetanetwork-utils` | [Utils](crates/utils.md) |
| `keetanetwork-block` | [Block](crates/block.md) |
| `keetanetwork-vote` | [Vote](crates/vote.md) |
| `keetanetwork-client` | [Client](crates/client.md) |
| `keetanetwork-bindings` | [Bindings](crates/bindings.md) |
| `keetanetwork-client-wasm` | [Client wasm](crates/client-wasm.md) |
| `keetanetwork-client-wasi` | [Client WASI](crates/client-wasi.md) |

`keetanetwork-node` and `keetanetwork-ledger` have no crate note. Those `lib.rs` files export no types.

## Where the tree lives

| Path | Role |
| --- | --- |
| Root `README.md` | Thin pointer into this tree |
| `docs/README.md` | This overview |
| `docs/STANDARD.md` | Documentation contract |
| `docs/ARCHITECTURE.md` | Collaboration graph and interaction path |
| `docs/QUICKSTART.md` | Install, build, test, and first use |
| `docs/crates/*` | Per-crate consumer contracts |
| `docs/concepts/*` | Single-topic pages that pass the inclusion test |

GitHub issues and pull requests stay the history home.

## Day-to-day

### Tooling

- The toolchain pin is Rust `1.94.0` in `rust-toolchain.toml`.
- The primary targets are `make developer`, `make build`, `make build release=1`, and `make check`.
- `make test` and the wasm or WASI test targets need GitHub Packages read. [Quickstart](QUICKSTART.md) holds the cargo-only path.
- Crate rustdoc opens through `make do-docs`.

### Where to put work

| Change | Place |
| --- | --- |
| A crate-boundary invariant | The crate source, then [Architecture](ARCHITECTURE.md) and the crate note |
| An install or build step | `Makefile`, then [Quickstart](QUICKSTART.md) |
| A documentation page | This tree, then the next-question table on this guide. Writers follow [Documentation Standard](STANDARD.md). |
| A public type contract | rustdoc on that type |

### First-week reading order

1. This guide.
2. [Architecture](ARCHITECTURE.md).
3. The crate note for the crate under change.
4. [Quickstart](QUICKSTART.md).
5. [Documentation Standard](STANDARD.md) before a docs edit.
6. The crate `lib.rs` rustdoc for the crate under change.

## Cultural one-liners

- **Make owns the build.** Prefer the `Makefile` targets over raw tool invocations.
- **The toolchain file wins after clone.** `rust-toolchain.toml` selects Rust `1.94.0`.
- **Release build is `make build release=1`.** That target is not `make release`.
- **Stubs stay stubs.** `keetanetwork-node` and `keetanetwork-ledger` have no product types.
- **rustdoc is the API reference.** This tree holds cross-file contracts.
- **Packages read is a test gate.** `cargo check` and `cargo build` stay open without it.

## Falsified by

- A change to the living documentation map that the first-week links follow.
- A change to the workspace `members` list in root `Cargo.toml`.
- A change that adds product types to `keetanetwork-node` or `keetanetwork-ledger`.
- A change to the license strings in root `LICENSE`, workspace `Cargo.toml`, or `keetanetwork-utils/node-harness/package.json`.
