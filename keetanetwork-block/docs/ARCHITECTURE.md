# Block

## Abstract

This page is the consumer contract for `keetanetwork-block`. The crate owns `Block`, `BlockBuilder`, `Operation`, and `AccountRef`. Opening-hash and signing rules live here. The client builder uses the same rules.

## Purpose

An engineer reads this page before changing how a first block or a successor is signed. After reading, the engineer knows which types this crate owns and which crates must keep using them.

## Ownership

`keetanetwork-block` owns the signed block and the operations it carries. `AccountRef` wraps a `GenericAccount` from `keetanetwork-account`. Opening-hash calculation and `sign` live on the block types.

The rustdoc example in `keetanetwork-block/src/lib.rs` builds a signed opening block through `BlockBuilder::default()`, `as_opening`, and `sign`. A live harness cookbook lives in `keetanetwork-block/tests/e2e.rs`. TypeScript compatibility tests live in `keetanetwork-block/tests/typescript_compat.rs`.

Field lists stay in rustdoc.

## Who consumes this crate

`keetanetwork-vote` covers block hashes. `keetanetwork-client` assembles blocks through `TransactionBuilder` and transmits them inside a staple. `keetanetwork-bindings` and the host ABI crates project the same block types.

[Account](../../keetanetwork-account/docs/ARCHITECTURE.md) holds the identity types. [Vote](../../keetanetwork-vote/docs/ARCHITECTURE.md) holds the commitment that covers those hashes. [Architecture](../../docs/ARCHITECTURE.md) holds the collaboration path.

## Feature contract

Default features are `std` and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`, `keetanetwork-account`, `keetanetwork-crypto`, and `keetanetwork-x509`.

This crate depends on `keetanetwork-error`, `keetanetwork-utils`, `keetanetwork-crypto` with `signature`, `keetanetwork-account`, `keetanetwork-asn1`, and `keetanetwork-x509`.

A `no_std` consumer enables `alloc` and at least one of `der` or `rasn`. [ASN.1](../../keetanetwork-asn1/docs/ARCHITECTURE.md) holds the codec contract.

## Falsified by

A change to `Block`, `BlockBuilder`, `Operation`, or `AccountRef` ownership. A change that lets `keetanetwork-client` compute an opening hash without this crate. A change to the rustdoc example in `keetanetwork-block/src/lib.rs`. A change to the `der` / `rasn` forwarding in `keetanetwork-block/Cargo.toml`.
