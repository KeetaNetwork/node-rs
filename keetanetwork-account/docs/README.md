# keetanetwork-account

This crate owns typed and type-erased identities for the workspace. `Account` is bound to one `KeyPairType`. `GenericAccount` is the type-erased account used at crate boundaries. `CertSigner` and `CertVerifier` sign and verify X.509-shaped artifacts.

## Quickstart

Default features are `std` and `rasn`. `std` implies `alloc`. Features `der` and `rasn` forward to `keetanetwork-asn1`.

```bash
cargo test -p keetanetwork-account
```

`make test-feat` also runs this crate with `std,der` and `std,rasn`.

## Examples

### Create from seed and sign

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
assert!(account.verify(message, &signature, None).is_ok());
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Identifier account

From `keetanetwork-account/src/account.rs` rustdoc.

```rust
use keetanetwork_account::{Account, KeyNETWORK, KeyPairType};

let network_account = Account::<KeyNETWORK>::generate_network_address(12345)?;
let token_account = network_account.generate_identifier(KeyPairType::TOKEN, None, 0)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
