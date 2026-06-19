//! WebAssembly bindings for the `keetanetwork-client` crate.
//!
//! Build the package with `wasm-pack build --target web`, then drive it from
//! the browser.
//!
//! # Conventions
//!
//! - Amounts are decimal **strings** (`"1000"`), never JS `number`.
//! - Cryptographic bytes (`sign`/`verify`/`encrypt`/`decrypt`) are
//!   `Uint8Array`; hashes and keys are hex strings.
//! - Errors are JS `Error` objects carrying a stable `error.code` for
//!   programmatic handling (e.g. `INVALID_PERMISSION_FLAG`).
//!
//! # Example
//!
//! ```js
//! import init, { KeetaClient, UserClient, Account, TransmitOptions } from './pkg/keetanetwork_client_wasm.js';
//!
//! // Instantiate the wasm module once.
//! await init();
//!
//! // Named network (resolves representatives + id), or `new KeetaClient(url)`
//! // plus `.withNetwork(id)` for a custom endpoint.
//! const client = KeetaClient.forNetwork('test');
//!
//! // Derive an account (algorithm defaults to ecdsa_secp256k1).
//! const me = Account.fromSeed(Account.generateSeed(), 0);
//! const token = Account.fromAddress('keeta_...token...');
//! const to = Account.fromAddress('keeta_...recipient...');
//!
//! // High-level signed write: send(to, amount, token).
//! const user = UserClient.fromClient(client, me);
//! await user.send(to, '1000', token);
//!
//! // Or assemble a multi-operation block and transmit it as one round.
//! const builder = user.initBuilder();
//! builder.send(to, '250', token);
//! await user.transmit(await builder.build(), new TransmitOptions());
//!
//! // Sign / verify arbitrary bytes.
//! const message = new TextEncoder().encode('hello');
//! const signature = me.sign(message);
//! const ok = me.verify(message, signature); // true
//!
//! try {
//!   await user.send(to, 'not-a-number', token);
//! } catch (error) {
//!   console.error(error.code, error.message); // INVALID_AMOUNT ...
//! }
//! ```

extern crate alloc;

#[cfg(target_family = "wasm")]
mod account;
#[cfg(target_family = "wasm")]
mod block;
#[cfg(target_family = "wasm")]
mod builder;
#[cfg(target_family = "wasm")]
mod certificate;
#[cfg(target_family = "wasm")]
mod client;
#[cfg(target_family = "wasm")]
mod convert;
#[cfg(target_family = "wasm")]
mod dto;
#[cfg(target_family = "wasm")]
mod options;
#[cfg(target_family = "wasm")]
mod pending;
#[cfg(target_family = "wasm")]
mod permissions;
#[cfg(target_family = "wasm")]
mod rep;
#[cfg(target_family = "wasm")]
mod swap;
#[cfg(target_family = "wasm")]
mod user;
#[cfg(target_family = "wasm")]
mod vote;
