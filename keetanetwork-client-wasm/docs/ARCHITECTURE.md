# Client wasm

## Abstract

This page is the consumer contract for `keetanetwork-client-wasm`. The crate is the browser ABI over `keetanetwork-client` and `keetanetwork-bindings`. Amounts are decimal strings. Errors carry `error.code`.

## Purpose

An engineer reads this page before changing the browser ABI or adding a JavaScript number amount. After reading, the engineer knows the conventions this crate guarantees and which crates it projects.

## Ownership

`keetanetwork-client-wasm` projects `KeetaClient`, `UserClient`, and account helpers into JavaScript. Crate rustdoc in `keetanetwork-client-wasm/src/lib.rs` holds the conventions and the JavaScript example.

Amounts are decimal strings such as `"1000"`. They are not JavaScript `number` values. Cryptographic bytes are `Uint8Array`. Hashes and keys are hex strings. Errors are JavaScript `Error` objects that carry a stable `error.code`.

`make build-wasm` runs `wasm-pack build` for this crate. Playwright cookbooks live in `keetanetwork-client-wasm/tests/roundtrip.spec.ts` and `keetanetwork-client-wasm/tests/fee.spec.ts`. [Quickstart](../../docs/QUICKSTART.md) names the Make targets and the Packages gate.

## Who this crate projects

This crate depends on `keetanetwork-client` with the `wasm` feature. It depends on `keetanetwork-bindings` with the `client` feature. It also depends on `keetanetwork-account`, `keetanetwork-block`, `keetanetwork-crypto`, `keetanetwork-x509`, and `keetanetwork-asn1`.

[Client](../../keetanetwork-client/docs/ARCHITECTURE.md) holds the orchestrator and the `http` plus `wasm` pairing. [Bindings](../../keetanetwork-bindings/docs/ARCHITECTURE.md) holds the shared projection. [Architecture](../../docs/ARCHITECTURE.md) holds the collaboration path.

## Feature contract

The client `wasm` feature enables `http` on `wasm32-unknown-unknown`. That pairing satisfies the `compile_error!` in `keetanetwork-client/src/lib.rs`.

## Falsified by

A change that accepts a JavaScript `number` as an amount. A change that drops `error.code` from thrown errors. A change that builds this crate without `keetanetwork-client` feature `wasm` or `keetanetwork-bindings` feature `client`. A change to the rustdoc example in `keetanetwork-client-wasm/src/lib.rs`.
