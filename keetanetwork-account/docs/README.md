# keetanetwork-account

This crate owns typed and type-erased identities for the workspace. `Account` is bound to one `KeyPairType`. `GenericAccount` is the type-erased account used at crate boundaries. `CertSigner` and `CertVerifier` sign and verify X.509-shaped artifacts. Block, vote, x509, client, and bindings crates consume these identities.

## Quickstart

Default features are `std` and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`.

```bash
cargo test -p keetanetwork-account
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Example

From `keetanetwork-account/src/account.rs` rustdoc.

```rust
use keetanetwork_account::{Account, KeyED25519};
use keetanetwork_crypto::algorithms::ed25519::Ed25519Derivation;
use keetanetwork_crypto::prelude::KeyDerivation;
use keetanetwork_crypto::utils::generate_random_seed;

let seed = generate_random_seed()?;
let private_key = Ed25519Derivation::derive_from_seed(seed)?;
let account = Account::<KeyED25519>::from(private_key);

let message = b"Hello, Keeta Network!";
let signature = account.sign(message, None)?;
let is_valid = account.verify(message, &signature, None);
assert!(is_valid.is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
