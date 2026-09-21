# Bindings

## Abstract

This page is the consumer contract for `keetanetwork-bindings`. The crate is the shared, target-agnostic projection used by the browser and WASI ABIs. It owns input parsing, account-algorithm mapping, and core-error reduction so those ABIs do not each grow a second copy.

## Purpose

An engineer reads this page before adding host-facing parsing in `keetanetwork-client-wasm` or `keetanetwork-client-wasi`. After reading, the engineer knows which work stays in this crate and which work stays in a target crate.

## Ownership

`keetanetwork-bindings` owns the shared projection. Crate rustdoc in `keetanetwork-bindings/src/lib.rs` states that each FFI boundary repeats the same input parsing, account-algorithm mapping, and core-error reduction.

This crate depends on `keetanetwork-account`, `keetanetwork-crypto`, `keetanetwork-block`, `keetanetwork-vote`, `keetanetwork-x509`, and `keetanetwork-asn1` with `alloc` and `rasn`. Feature `client` pulls optional `keetanetwork-client`.

Field lists stay in rustdoc.

## Who consumes this crate

`keetanetwork-client-wasm` depends on this crate with the `client` feature. `keetanetwork-client-wasi` depends on this crate on every build. Feature `p2` on the WASI crate also enables `keetanetwork-bindings/client`.

[Client wasm](client-wasm.md) holds the browser ABI conventions. [Client WASI](client-wasi.md) holds the `p1` / `p2` contract. [Architecture](../ARCHITECTURE.md) holds the collaboration path.

## Feature contract

Default features include `std`. Feature `client` is opt-in and enables `keetanetwork-client`.

A target crate that only needs the pure projection leaves `client` off. A target crate that needs the HTTP orchestrator enables `client`.

## Falsified by

A change that moves account-algorithm mapping or core-error reduction into `keetanetwork-client-wasm` or `keetanetwork-client-wasi` without this crate. A change to the `client` feature in `keetanetwork-bindings/Cargo.toml`. A change that drops this crate from either host ABI crate.
