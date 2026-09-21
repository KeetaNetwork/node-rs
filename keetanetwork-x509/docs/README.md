# keetanetwork-x509

This crate owns X.509 certificate builders, stores, and validation. Account crate traits `CertSigner` and `CertVerifier` sign and verify those artifacts. Block, bindings, and the host ABI crates consume the resulting certificates.

## Quickstart

Default features are `std`, `serde`, and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`.

```bash
cargo test -p keetanetwork-x509
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

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

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
