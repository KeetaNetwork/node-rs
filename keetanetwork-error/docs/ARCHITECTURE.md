# Error

## Abstract

This page is the consumer contract for `keetanetwork-error`. The crate owns shared error types that higher crates return and that the client re-exports. It also names the node error categories that a decoded envelope can carry.

## Purpose

An engineer reads this page before introducing a crate-local error envelope that callers must learn twice. After reading, the engineer knows which types this crate owns and which crate re-exports them to HTTP callers.

## Ownership

`keetanetwork-error` owns `KeetaNetError` and `NodeErrorType` in `keetanetwork-error/src/lib.rs`. `NodeErrorType` is the category taken from the `type` field of a node error envelope. The known categories are `Account`, `Api`, `Block`, `Certificate`, `Client`, `Kv`, `Ledger`, `Permissions`, `Vote`, and `Generic`.

Field lists and variant payloads stay in rustdoc.

## Who consumes this crate

`keetanetwork-account`, `keetanetwork-block`, `keetanetwork-vote`, `keetanetwork-x509`, and `keetanetwork-client` depend on this crate. `keetanetwork-client` re-exports `KeetaNetError` and `NodeErrorType` from `keetanetwork-client/src/lib.rs`.

`keetanetwork-crypto` takes this crate only when the `std` feature is on.

[Architecture](../../docs/ARCHITECTURE.md) holds the collaboration graph.

## Feature contract

Default features include `std`. `std` implies `alloc`. The crate builds under `no_std` with `alloc`.

A higher crate that needs formatted errors on native targets enables `keetanetwork-error/std`. A `no_std` consumer enables `alloc` only.

## Falsified by

A change to `KeetaNetError` or `NodeErrorType` in `keetanetwork-error/src/lib.rs`. A change that drops the client re-export of those two types from `keetanetwork-client/src/lib.rs`. A change to the `std` / `alloc` features in `keetanetwork-error/Cargo.toml`.
