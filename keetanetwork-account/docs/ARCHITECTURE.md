# Account

## Abstract

This page is the consumer contract for `keetanetwork-account`. The crate owns typed and type-erased identities plus the certificate signing traits. Block, vote, x509, client, and bindings crates consume those identities.

## Purpose

An engineer reads this page before changing an identity type or adding a second account model in a higher crate. After reading, the engineer knows which types this crate owns and which crates must keep consuming them.

## Ownership

`keetanetwork-account` owns `Account`, `GenericAccount`, `KeyPairType`, and identifier accounts. `Account` is the typed identity bound to one `KeyPairType`. `GenericAccount` is the type-erased account used at crate boundaries. `KeyPairType` names signing algorithms and identifier accounts.

`CertSigner` signs X.509-shaped artifacts in certificate mode. `CertVerifier` verifies those certificate-mode signatures. Certificate builders and stores stay in `keetanetwork-x509`.

Crate rustdoc on `keetanetwork-account/src/lib.rs` names those types. Field lists stay in rustdoc.

## Who consumes this crate

| Consumer | How it uses the identities |
| --- | --- |
| `keetanetwork-block` | `AccountRef` wraps `GenericAccount`. Opening-hash and signing use the same account |
| `keetanetwork-vote` | A vote issuer is an `AccountRef` |
| `keetanetwork-x509` | Builders call `CertSigner` and `CertVerifier` |
| `keetanetwork-client` | `KeetaClient` and `UserClient` take an `AccountRef` |
| `keetanetwork-bindings` | Host ABIs map account algorithms through this crate |

[Architecture](../../docs/ARCHITECTURE.md) holds the collaboration graph. This page does not redraw it.

## Feature contract

Default features are `std` and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1` and `keetanetwork-crypto`.

A `no_std` consumer enables `alloc` and at least one of `der` or `rasn` when it needs the ASN.1 path. [ASN.1](../../keetanetwork-asn1/docs/ARCHITECTURE.md) holds the at-least-one codec contract.

This crate depends on `keetanetwork-crypto` with `signature` and `encryption`. It depends on `keetanetwork-error` and `keetanetwork-utils`. `keetanetwork-asn1` is optional behind `der` and `rasn`.

## Seed and identifier tests

Account seed, identifier, and signature cookbooks live in `keetanetwork-account/tests/account_creation.rs`, `keetanetwork-account/tests/seed_derivation.rs`, `keetanetwork-account/tests/identifier_accounts.rs`, and `keetanetwork-account/tests/signatures.rs`.

## Falsified by

A change that moves `Account`, `GenericAccount`, `KeyPairType`, `CertSigner`, or `CertVerifier` off this crate. A change that adds a second identity model in `keetanetwork-block`, `keetanetwork-vote`, `keetanetwork-x509`, `keetanetwork-client`, or `keetanetwork-bindings`. A change to the `der` / `rasn` forwarding in `keetanetwork-account/Cargo.toml`.
