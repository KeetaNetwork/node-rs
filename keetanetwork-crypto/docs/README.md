# keetanetwork-crypto

This crate owns algorithm-agnostic primitives for keys, hashes, signatures, and encryption. Account, block, and vote crates call these modules. They do not embed a second crypto stack.

## Quickstart

Default features are `std`, `signature`, `encryption`, and `rasn`. `std` implies `alloc`.

```bash
cargo test -p keetanetwork-crypto
```

`make test-feat` also runs this crate with `std,signature`, `std,encryption`, `std,der`, and `std`.

## Examples

### Default hash

From `keetanetwork-crypto/src/hash.rs` `hash_default`.

```rust
use keetanetwork_crypto::hash::hash_default;

let digest = hash_default(b"hello world");
assert_eq!(digest.len(), 32);
```

### Random seed

From `keetanetwork-crypto/src/utils.rs` `test_generate_random_seed`.

```rust
use keetanetwork_crypto::prelude::ExposeSecret;
use keetanetwork_crypto::utils::generate_random_seed;

let seed = generate_random_seed()?;
assert_eq!(seed.expose_secret().len(), 32);
assert_ne!(*seed.expose_secret(), [0u8; 32]);
# Ok::<(), keetanetwork_crypto::error::CryptoError>(())
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
