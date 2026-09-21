# Crypto

## Abstract

This page is the consumer contract for `keetanetwork-crypto`. The crate owns algorithm-agnostic primitives for keys, hashes, signatures, and encryption. Account, block, vote, client, and bindings crates call those primitives. They do not embed a second crypto stack.

## Purpose

An engineer reads this page before adding a signing or hashing path in a higher crate. After reading, the engineer knows which features this crate exposes and which crates must keep depending on it.

## Ownership

`keetanetwork-crypto` owns key generation, derivation, public-key formatting, hashing, signatures, and encryption. The crate rustdoc in `keetanetwork-crypto/src/lib.rs` names support for `secp256k1` and `Ed25519`.

`Hashable` and the signing prelude live in this crate. `keetanetwork-block` and `keetanetwork-vote` hash and sign through those types.

Field lists stay in rustdoc.

## Who consumes this crate

| Consumer | How it uses this crate |
| --- | --- |
| `keetanetwork-account` | Enables `signature` and `encryption` for account keys |
| `keetanetwork-block` | Enables `signature` for block signing |
| `keetanetwork-vote` | Enables `signature` for vote signing |
| `keetanetwork-x509` | Uses the same primitives for certificate material |
| `keetanetwork-client` | Depends on `alloc` for client-side hashing |
| `keetanetwork-bindings` | Depends on `alloc` and `signature` for host ABIs |

[Architecture](../../docs/ARCHITECTURE.md) holds the collaboration graph.

## Feature contract

Default features are `std`, `signature`, `encryption`, and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to optional `keetanetwork-asn1`.

`keetanetwork-error` is optional and comes on with `std`. `keetanetwork-utils` is a path dependency.

A `no_std` consumer enables `alloc` plus `signature` or `encryption` as the call site needs. [ASN.1](../../keetanetwork-asn1/docs/ARCHITECTURE.md) holds the codec contract when `der` or `rasn` is on.

## Example

From `keetanetwork-crypto/src/hash.rs` `hash_default`.

```rust
use keetanetwork_crypto::hash::hash_default;

let digest = hash_default(b"hello world");
assert_eq!(digest.len(), 32);
```

## Falsified by

A change that moves hashing or signing primitives out of `keetanetwork-crypto`. A change that lets `keetanetwork-account`, `keetanetwork-block`, or `keetanetwork-vote` sign without this crate. A change to the `signature`, `encryption`, `der`, or `rasn` features in `keetanetwork-crypto/Cargo.toml`.
