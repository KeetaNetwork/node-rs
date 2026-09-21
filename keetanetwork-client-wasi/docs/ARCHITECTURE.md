# Client WASI

## Abstract

This page is the consumer contract for `keetanetwork-client-wasi`. The crate is the WASI ABI over a shared `pure` module. A WASI build selects exactly one of `p1` or `p2`. Feature `p2` pulls `keetanetwork-client`. Feature `p1` stays on the pure surface.

## Purpose

An engineer reads this page before changing a WASI feature or adding a second networking path on `p1`. After reading, the engineer knows which feature a P1 or P2 build enables and which crate supplies HTTP.

## Ownership

`keetanetwork-client-wasi` owns two feature-selected flavors over one shared `pure` module in `keetanetwork-client-wasi/src/lib.rs`.

Feature `p2` on `wasm32-wasip2` is a `wit-bindgen` component. It networks over `wasi:http` and exposes the pure surface. That feature pulls `keetanetwork-client` with the `wasi` feature and enables `keetanetwork-bindings/client`.

Feature `p1` on `wasm32-wasip1` is a core module. It exposes the pure surface over a flat ABI. P1 has no outbound `connect`. The host dials.

A WASI build enables exactly one of `p1` or `p2`. The `compile_error!` in `keetanetwork-client-wasi/src/lib.rs` is the enforcement point. Off a WASI target both features compile out and leave `pure`.

Host tests live under `keetanetwork-client-wasi/host-tests/`. [Quickstart](../../docs/QUICKSTART.md) names `make build-wasi` and `make test-wasi`. Those targets select `p1` for `wasm32-wasip1` and `p2` for `wasm32-wasip2`.

## Who this crate projects

This crate always depends on `keetanetwork-account`, `keetanetwork-block`, `keetanetwork-crypto`, `keetanetwork-vote`, `keetanetwork-x509`, and `keetanetwork-bindings`. Feature `p2` adds `keetanetwork-client`.

[Client](../../keetanetwork-client/docs/ARCHITECTURE.md) holds the `wasi` feature that supplies codec types without Tokio. [Bindings](../../keetanetwork-bindings/docs/ARCHITECTURE.md) holds the shared projection. [Architecture](../../docs/ARCHITECTURE.md) holds the collaboration path.

## Feature contract

Select exactly one of `p1` or `p2` per WASI build. Feature `p2` is the only edge from this crate to `keetanetwork-client`. Feature `p1` stays on the pure surface.

## Falsified by

A change to the `compile_error!` in `keetanetwork-client-wasi/src/lib.rs`. A change that lets a WASI build enable both `p1` and `p2`, or neither. A change that pulls `keetanetwork-client` on feature `p1`. A change to the `p1` / `p2` selection in the `Makefile` `build-wasi` or `test-wasi` targets.
