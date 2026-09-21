# Client

## Abstract

This page is the consumer contract for `keetanetwork-client`. The crate owns `KeetaClient`, `UserClient`, and `TransactionBuilder`. HTTP transport is generated from the committed OpenAPI document. The crate re-exports the consumer-facing vote types.

## Purpose

An engineer reads this page before changing client construction, HTTP generation, or the `http` runtime pairing. After reading, the engineer knows which types this crate owns and which features a native or browser build enables.

## Ownership

`KeetaClient` is the orchestrator. `UserClient` signs and transmits on behalf of an account. `TransactionBuilder` assembles blocks with the same opening-hash and signing rules as `keetanetwork-block`.

HTTP transport is generated at build time from `keetanetwork-client/openapi/keetanet-node.yaml` through progenitor. The generated types are exposed as the `generated` module when the `codec` feature is on.

The rustdoc example in `keetanetwork-client/src/lib.rs` constructs `KeetaClient::new("http://localhost:8080/api")` and `.with_network(0u8)`. A live harness cookbook lives in `keetanetwork-client/tests/e2e.rs`. `UserClient` signing tests live in `keetanetwork-client/tests/user_signing.rs`. [Quickstart](../QUICKSTART.md) cites those examples.

The crate re-exports `Vote`, `VoteQuote`, `VoteStaple`, and `VoteBlockHash` from `keetanetwork-vote`. It also re-exports `KeetaNetError` and `NodeErrorType` from `keetanetwork-error`.

## Feature contract

Default features include `std`. Feature `std` enables `http` and a native Tokio runtime. Feature `wasm` enables `http` on `wasm32-unknown-unknown`. Feature `wasi` enables `codec` without pulling Tokio.

Feature `http` pairs with a runtime. Native builds enable `std`. Browser builds enable `wasm` on `wasm32-unknown-unknown`. The `compile_error!` in `keetanetwork-client/src/lib.rs` is the enforcement point.

The orchestrator is `no_std` plus `alloc` when `std`, `http`, and `wasi` are off. A `no_std` consumer supplies a `Runtime` and a `NodeTransport` through `KeetaClient::with_parts`.

## Who consumes this crate

`keetanetwork-client-wasm` enables the `wasm` feature. `keetanetwork-client-wasi` enables this crate only on feature `p2`. `keetanetwork-bindings` takes this crate behind its `client` feature.

[Block](block.md) and [Vote](vote.md) hold the signed objects. [Bindings](bindings.md) holds the shared host projection. [Architecture](../ARCHITECTURE.md) holds the collaboration path.

## Falsified by

A change to `KeetaClient`, `UserClient`, or `TransactionBuilder` ownership. A change that moves the OpenAPI document away from `keetanetwork-client/openapi/keetanet-node.yaml`. A change to the `compile_error!` that pairs `http` with a runtime. A change that drops the vote or error re-exports from `keetanetwork-client/src/lib.rs`.
