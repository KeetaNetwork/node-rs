# X.509

## Abstract

This page is the consumer contract for `keetanetwork-x509`. The crate owns certificate builders and stores. Account crate traits sign and verify those artifacts. Block, bindings, and the host ABI crates consume the resulting certificates.

## Purpose

An engineer reads this page before adding a certificate builder in another crate. After reading, the engineer knows the split between account traits and x509 builders, and which crates consume the builders.

## Ownership

`keetanetwork-x509` owns builders, parsers, stores, and validation for X.509 certificates. Crate rustdoc in `keetanetwork-x509/src/lib.rs` is the field reference.

`CertSigner` and `CertVerifier` live on `keetanetwork-account`. This crate calls those traits. It does not grow a second signer trait.

Builder, bundle, and validation cookbooks live in `keetanetwork-x509/tests/builders.rs`, `keetanetwork-x509/tests/bundles.rs`, and `keetanetwork-x509/tests/validation.rs`.

## Who consumes this crate

`keetanetwork-block` depends on this crate so a block can carry certificate material. `keetanetwork-bindings`, `keetanetwork-client-wasm`, and `keetanetwork-client-wasi` depend on this crate so host ABIs can project certificates.

[Account](../../keetanetwork-account/docs/ARCHITECTURE.md) holds the signer and verifier traits. [Architecture](../../docs/ARCHITECTURE.md) holds the collaboration graph.

## Feature contract

Default features are `std`, `serde`, and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`, `keetanetwork-crypto`, and `keetanetwork-account`.

The crate build depends on `keetanetwork-utils` with the `build` feature. [Utils](../../keetanetwork-utils/docs/ARCHITECTURE.md) holds that helper.

A `no_std` consumer enables `alloc` and at least one of `der` or `rasn`. [ASN.1](../../keetanetwork-asn1/docs/ARCHITECTURE.md) holds the at-least-one codec contract.

## Example

From `keetanetwork-x509/src/builder.rs` rustdoc.

```rust
use keetanetwork_account::{Account, KeyED25519};
use keetanetwork_asn1::SubjectPublicKeyInfo;
use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
use keetanetwork_crypto::prelude::KeyDerivation;
use keetanetwork_crypto::utils::generate_random_seed;
use keetanetwork_x509::builder::CertificateBuilder;
use keetanetwork_x509::{oids, utils, SerialNumber};

let seed = generate_random_seed()?;
let private_key = Ed25519Derivation::derive_from_seed(seed)?;
let account = Account::<KeyED25519>::from(private_key);
let public_key_info = SubjectPublicKeyInfo::from(account.keypair.to_public_key());
let subject_dn = utils::create_dn(&[(oids::CN, "Example Certificate")])?;

let certificate = CertificateBuilder::new()
	.with_subject_public_key(public_key_info.clone())
	.with_subject_dn(subject_dn.clone())
	.with_issuer_dn(subject_dn)
	.with_serial_number(SerialNumber::from(1u64))
	.with_validity_days(365)
	.build(&account)?;
assert!(certificate.verify_signature(&public_key_info).is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Falsified by

A change that moves certificate builders or stores off `keetanetwork-x509`. A change that adds a signer trait on this crate that duplicates `CertSigner` or `CertVerifier`. A change to the `der` / `rasn` forwarding in `keetanetwork-x509/Cargo.toml`.
