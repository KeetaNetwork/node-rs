# keetanetwork-x509

This crate owns X.509 certificate builders, stores, and validation. Account crate traits `CertSigner` and `CertVerifier` sign and verify those artifacts. Block, bindings, and the host ABI crates consume the resulting certificates.

## Quickstart

Default features are `std`, `serde`, and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`.

```bash
cargo test -p keetanetwork-x509
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Example

From `keetanetwork-x509/src/utils.rs` rustdoc on `create_dn`.

```rust
use keetanetwork_asn1::oids;
use keetanetwork_x509::utils::create_dn;

let pairs = &[
	(oids::CN, "example.com"),
	(oids::O, "Example Organization"),
];

let dn = create_dn(pairs)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
