# Overview

## Abstract

This guide is the table of contents for the `node-rs` workspace documentation. Workspace contracts live on [Architecture](ARCHITECTURE.md), [Quickstart](QUICKSTART.md), and [Documentation Standard](STANDARD.md). Each product crate holds its architecture under that crate `docs/` directory.

## Purpose

An engineer reads this guide to find the page that holds each inbound question. After reading, the engineer can open the workspace page or the crate `docs/` entry that owns that question.

| Next question | The page |
| --- | --- |
| How do the crates depend on and call each other? | [Architecture](ARCHITECTURE.md) |
| How does a reader install, build, and test? | [Quickstart](QUICKSTART.md) |
| How does a writer review a page in this tree? | [Documentation Standard](STANDARD.md) |
| Where do account identities live? | [Account](../keetanetwork-account/docs/README.md) |
| Where do shared errors live? | [Error](../keetanetwork-error/docs/README.md) |
| Where do signing primitives live? | [Crypto](../keetanetwork-crypto/docs/README.md) |
| Where do certificate builders live? | [X.509](../keetanetwork-x509/docs/README.md) |
| Where does the ASN.1 codec contract live? | [ASN.1](../keetanetwork-asn1/docs/README.md) |
| Where do test helpers and the harness live? | [Utils](../keetanetwork-utils/docs/README.md) |
| Where do opening-hash and block signing live? | [Block](../keetanetwork-block/docs/README.md) |
| Where do vote, quote, and staple live? | [Vote](../keetanetwork-vote/docs/README.md) |
| Where do `KeetaClient` and HTTP generation live? | [Client](../keetanetwork-client/docs/README.md) |
| Where does the shared host projection live? | [Bindings](../keetanetwork-bindings/docs/README.md) |
| Where does the browser ABI live? | [Client wasm](../keetanetwork-client-wasm/docs/README.md) |
| Where does the WASI `p1` / `p2` contract live? | [Client WASI](../keetanetwork-client-wasi/docs/README.md) |
| Where are the reserved stub crates named? | [Node](../keetanetwork-node/docs/README.md) and [Ledger](../keetanetwork-ledger/docs/README.md) |

## What this workspace is

This repository is a Cargo workspace of Keeta Network node crates. Root `Cargo.toml` `[workspace].members` is the member list. Crate identity lives in each member `Cargo.toml` `description` plus rustdoc on that crate `lib.rs`.

Each product crate listed on this guide holds architecture on that crate `docs/ARCHITECTURE.md`. The crate `docs/README.md` is the thin entry. `keetanetwork-node` and `keetanetwork-ledger` are empty stubs. Those crates hold a minimal `docs/README.md` only. [Architecture](ARCHITECTURE.md) names that boundary.

Each member crate carries its own version in that crate `Cargo.toml`. This guide does not treat the unused workspace package version as the repository version. This table of contents does not stamp versions.

The files state three license strings. Root `LICENSE` is the Keeta Token Network Community License (v1.0). Workspace `Cargo.toml` `license` is `MIT`. `keetanetwork-utils/node-harness/package.json` `license` is `Keeta Token Network Community License`. This guide cites those files as written.

## Crate docs

These entries are the living table of contents for crate documentation. [Architecture](ARCHITECTURE.md) draws the collaboration graph. Each crate architecture names the crates that call that crate.

| Crate | Entry |
| --- | --- |
| `keetanetwork-account` | [Account](../keetanetwork-account/docs/README.md) |
| `keetanetwork-error` | [Error](../keetanetwork-error/docs/README.md) |
| `keetanetwork-crypto` | [Crypto](../keetanetwork-crypto/docs/README.md) |
| `keetanetwork-x509` | [X.509](../keetanetwork-x509/docs/README.md) |
| `keetanetwork-asn1` | [ASN.1](../keetanetwork-asn1/docs/README.md) |
| `keetanetwork-utils` | [Utils](../keetanetwork-utils/docs/README.md) |
| `keetanetwork-block` | [Block](../keetanetwork-block/docs/README.md) |
| `keetanetwork-vote` | [Vote](../keetanetwork-vote/docs/README.md) |
| `keetanetwork-client` | [Client](../keetanetwork-client/docs/README.md) |
| `keetanetwork-bindings` | [Bindings](../keetanetwork-bindings/docs/README.md) |
| `keetanetwork-client-wasm` | [Client wasm](../keetanetwork-client-wasm/docs/README.md) |
| `keetanetwork-client-wasi` | [Client WASI](../keetanetwork-client-wasi/docs/README.md) |
| `keetanetwork-node` | [Node](../keetanetwork-node/docs/README.md) |
| `keetanetwork-ledger` | [Ledger](../keetanetwork-ledger/docs/README.md) |

## Where the tree lives

| Path | Role |
| --- | --- |
| Root `README.md` | Thin pointer into this tree |
| `docs/README.md` | This overview |
| `docs/STANDARD.md` | Documentation contract |
| `docs/ARCHITECTURE.md` | Collaboration graph and interaction path |
| `docs/QUICKSTART.md` | Install, build, test, and first use |
| `keetanetwork-*/docs/README.md` | Thin crate docs entry |
| `keetanetwork-*/docs/ARCHITECTURE.md` | Product-crate architecture |
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
| A crate-boundary invariant | The crate source, then [Architecture](ARCHITECTURE.md) and that crate `docs/ARCHITECTURE.md` |
| An install or build step | `Makefile`, then [Quickstart](QUICKSTART.md) |
| A documentation page | This tree or the crate `docs/` directory, then the next-question table on this guide. Writers follow [Documentation Standard](STANDARD.md). |
| A public type contract | rustdoc on that type |

### First-week reading order

1. This guide.
2. [Architecture](ARCHITECTURE.md).
3. The crate `docs/ARCHITECTURE.md` for the crate under change.
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
