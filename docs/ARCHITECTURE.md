# Architecture

## Abstract

This page states how the `node-rs` workspace is split and which states the tree forbids. Crate rustdoc and each `Cargo.toml` remain the field and dependency references. This page does not inventory members.

## Purpose

An engineer reads this page to learn why crates exist as separate packages and which combinations are illegal. After reading, the engineer knows where a cross-cutting contract lives and which alternatives stay closed.

## Related documents

- [Overview](README.md) for the cultural map and living index.
- [Quickstart](QUICKSTART.md) for install, build, test, and first use.
- [Documentation Standard](STANDARD.md) for the inclusion test and page shape.

## Why the workspace splits

The workspace separates four kinds of packages so each kind can change without forcing the others to move.

| Kind | Force that keeps it separate | Examples of the role |
| --- | --- | --- |
| Primitives and codecs | Shared encoding and crypto must stay usable under `no_std` / `alloc` feature matrices | `keetanetwork-crypto`, `keetanetwork-asn1`, `keetanetwork-error`, `keetanetwork-utils` |
| Domain identity and certificates | Account and X.509 rules are consumed by many higher crates | `keetanetwork-account`, `keetanetwork-x509` |
| Ledger domain objects | Block and vote rules are the signed objects the network exchanges | `keetanetwork-block`, `keetanetwork-vote` |
| Client and ABI projections | HTTP generation and host ABIs change on a different cadence than domain types | `keetanetwork-client`, `keetanetwork-bindings`, `keetanetwork-client-wasm`, `keetanetwork-client-wasi` |

`keetanetwork-node` and `keetanetwork-ledger` keep reserved crate names in the workspace. Their `lib.rs` files export no types on this tip. They are placeholders, not product surfaces.

Crate identity, versions, and dependency edges live in each member `Cargo.toml` and in rustdoc. This page does not restate those lists.

## Illegal states

These combinations are forbidden on this tip. The build or the documentation contract rejects them.

| Illegal state | Where it fails | Legal alternative |
| --- | --- | --- |
| Treat `keetanetwork-node` or `keetanetwork-ledger` as a product API | Those `lib.rs` files export no types. This page names them as stubs only | Implement types in those crates first, then document them |
| Build `keetanetwork-asn1` with neither `der` nor `rasn` | `compile_error!` in `keetanetwork-asn1/src/lib.rs` | Enable at least one of `der` or `rasn`. Both may be on together |
| Enable client feature `http` without a runtime | `compile_error!` in `keetanetwork-client/src/lib.rs` | Pair `http` with `std` on native targets, or with `wasm` on `wasm32-unknown-unknown` |
| Enable both or neither of WASI features `p1` and `p2` on `keetanetwork-client-wasi` | `compile_error!` in `keetanetwork-client-wasi/src/lib.rs` | Select exactly one of `p1` or `p2` per WASI build |
| Add a per-crate README that only restates `pub use` | Inclusion test on [Documentation Standard](STANDARD.md) | Keep identity in `Cargo.toml` description plus rustdoc |

## SSOT homes for cross-cutting contracts

Each row is one body of knowledge. Other pages link here or to the named source. They do not restate field lists.

| Contract | Home |
| --- | --- |
| Account and identifier identity consumed across crates | `keetanetwork-account` rustdoc. Higher crates consume those types |
| Certificate signing and verification traits versus X.509 builders | Traits on `keetanetwork-account`. Builders and stores in `keetanetwork-x509` |
| Block opening-hash and signing rules | `keetanetwork-block` rustdoc and tests. The client builder uses the same rules |
| Vote versus quote versus staple | `keetanetwork-vote` rustdoc. The client re-exports the consumer-facing vote types |
| HTTP transport shape | `keetanetwork-client/openapi/keetanet-node.yaml` generated through progenitor into the client `generated` module |
| Browser and WASI ABIs | `keetanetwork-bindings` as the shared projection. Wasm amounts are decimal strings and errors carry `error.code`. WASI selects exactly one of `p1` or `p2` |

## Rejected alternatives

These decisions stay closed. A later change that reopens one is a migration.

| Decision | Rejected alternative | Why the alternative lost |
| --- | --- | --- |
| Crate identity lives in each `Cargo.toml` plus rustdoc | One README barrel per member crate | A barrel restates `pub use` and fails the inclusion test |
| Examples stay in crate rustdoc and tests | An `examples/` directory | No such directory exists on this tip. Scope keeps examples in-crate |
| Architecture names node and ledger as stubs | A node or ledger product page | Those `lib.rs` files export no types |
| Quickstart holds the PAT and Packages fact | Revival of branch `docs/add_pat_instructions` | That branch is stale and still taught `make release` as a release build |
| Architecture explains forces and illegal states | A member roster or a Mermaid copy of `Cargo.toml` edges | Rosters and edge copies go stale without teaching structure |

## Falsified by

A change that adds product types to `keetanetwork-node/src/lib.rs` or `keetanetwork-ledger/src/lib.rs`. A change to the `compile_error!` gates in `keetanetwork-asn1/src/lib.rs`, `keetanetwork-client/src/lib.rs` (`http` runtime pairing), or `keetanetwork-client-wasi/src/lib.rs` (`p1` / `p2`). A change that moves the OpenAPI document away from `keetanetwork-client/openapi/keetanet-node.yaml` as the HTTP transport source. A decision to add per-crate README barrels or an `examples/` directory.
