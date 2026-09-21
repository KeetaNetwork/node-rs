# keetanetwork-client-wasm

This crate is the browser ABI over `keetanetwork-client` and `keetanetwork-bindings`. Amounts are decimal strings. Errors carry `error.code`.

## Quickstart

This crate depends on `keetanetwork-client` with the `wasm` feature and `keetanetwork-bindings` with the `client` feature.

```bash
make build-wasm
make test-wasm
```

Those Make targets need GitHub Packages read. [Workspace Quickstart](../../docs/QUICKSTART.md) holds the Packages gate.

## Examples

### Send through UserClient

From `keetanetwork-client-wasm/src/lib.rs` rustdoc.

```js
import init, { KeetaClient, UserClient, Account, TransmitOptions } from './pkg/keetanetwork_client_wasm.js';

await init();
const client = KeetaClient.forNetwork('test');
const me = Account.fromSeed(Account.generateSeed(), 0);
const token = Account.fromPublicKeyString('keeta_...token...');
const to = Account.fromPublicKeyString('keeta_...recipient...');

const user = UserClient.fromClient(client, me);
await user.send(to, '1000', token);

const builder = user.initBuilder();
builder.send(to, '250', token);
await user.transmit(await builder.build(), new TransmitOptions());
```

### Sign, verify, and coded amount error

From `keetanetwork-client-wasm/src/lib.rs` rustdoc.

```js
import init, { KeetaClient, UserClient, Account } from './pkg/keetanetwork_client_wasm.js';

await init();
const client = KeetaClient.forNetwork('test');
const me = Account.fromSeed(Account.generateSeed(), 0);
const token = Account.fromPublicKeyString('keeta_...token...');
const to = Account.fromPublicKeyString('keeta_...recipient...');
const user = UserClient.fromClient(client, me);

const message = new TextEncoder().encode('hello');
const signature = me.sign(message);
const ok = me.verify(message, signature); // true

try {
  await user.send(to, 'not-a-number', token);
} catch (error) {
  console.error(error.code, error.message); // INVALID_AMOUNT
}
```

## Related documents

- [Architecture](ARCHITECTURE.md)
- [Workspace overview](../../docs/README.md)
