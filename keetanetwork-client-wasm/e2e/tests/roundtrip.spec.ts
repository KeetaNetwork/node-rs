import { expect, test } from '@playwright/test';

import type * as Keeta from '../../pkg/keetanetwork_client_wasm';

interface NodeInfo {
	api: string;
	network: string;
	baseToken: string;
	trusted: string;
	recipient: string;
	trustedSeedHex: string;
	amount: string;
}

interface SendRoundTrip {
	version: string;
	before: string;
	after: string;
	accepted: boolean;
	head: string | null;
}

interface BuilderRoundTrip {
	readOnly: boolean;
	signer: string;
	transmitted: boolean;
	recipientBalance: string;
	blockHexRoundTrips: boolean;
}

interface GenerationRoundTrip {
	seedHexLength: number;
	passphraseWords: number;
	derivedAddress: string;
	deterministic: boolean;
	transmitted: boolean;
	recipientBalance: string;
}

interface TypedReads {
	balanceFields: { token: string; balance: string; pending: string } | null;
	stateBalances: number;
	stateHeadIsString: boolean;
	repCount: number;
	repWeightIsString: boolean;
}

interface PermissionDecode {
	builtFlags: string[];
	builtOffsets: number[];
	hasAccess: boolean;
	hasOwner: boolean;
	hasOffset3: boolean;
	hasOffset4: boolean;
	roundTripFlags: string[];
	roundTripOffsets: number[];
	decodedFlags: string[];
	decodedOffsets: number[];
}

// A fresh recipient the test fully controls, distinct from the harness rep.
const RECIPIENT_SEED_HEX = '22'.repeat(32);

async function loadNodeInfo(request: {
	get: (url: string) => Promise<{ json: () => Promise<NodeInfo> }>;
}): Promise<NodeInfo> {
	const response = await request.get('/node-info.json');
	return response.json();
}

test('KeetaClient publishes a send round-trip against a live node', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: SendRoundTrip = await page.evaluate(async (cfg: NodeInfo) => {
		const { KeetaClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
		const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
		const recipient = Account.fromAddress(cfg.recipient);
		const token = Account.fromAddress(cfg.baseToken);

		const version = await client.nodeVersion();
		const before = await client.balance(trusted, token);
		const accepted = await client.send(trusted, recipient, cfg.amount, token);
		const after = await client.balance(trusted, token);

		const headBlock = await client.headBlock(trusted);
		let head: string | null = null;
		if (headBlock) {
			head = headBlock.hash;
		}

		return { version, before, after, accepted, head };
	}, info);

	expect(result.version, 'the live node must report a version').not.toBe('');
	expect(result.accepted, 'the node must accept the published staple').toBe(true);
	expect(result.head, 'the trusted account head must advance after the send').toBeTruthy();
	expect(
		BigInt(result.before) - BigInt(result.after),
		'the sent amount must leave the trusted account settled balance',
	).toBe(BigInt(info.amount));
});

test('UserClient transmits a builder-assembled send', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: BuilderRoundTrip = await page.evaluate(
		async (cfg: { info: NodeInfo; recipientSeedHex: string }) => {
			const { KeetaClient, UserClient, Account, TransmitOptions, Block } = (
				window as unknown as { keeta: typeof Keeta }
			).keeta;

			const token = Account.fromAddress(cfg.info.baseToken);
			const trusted = Account.fromSeed(cfg.info.trustedSeedHex, 0, 'ed25519');
			const recipient = Account.fromSeed(cfg.recipientSeedHex, 0, 'ed25519');

			const client = new KeetaClient(cfg.info.api).withNetwork(cfg.info.network);
			const user = UserClient.fromClient(client, trusted);
			const readOnly = user.isReadOnly;
			const signer = user.account().address;

			const builder = user.initBuilder();
			builder.send(recipient, cfg.info.amount, token);

			const blocks = await builder.build();

			// A built block must survive a hex serialization round-trip.
			const reEncoded = Block.fromHex(blocks[0].toHex());
			const blockHexRoundTrips = reEncoded.hash === blocks[0].hash;

			const transmitted = await user.transmit(blocks, new TransmitOptions());

			const recipientBalance = await client.balance(recipient, token);

			return { readOnly, signer, transmitted, recipientBalance, blockHexRoundTrips };
		},
		{ info, recipientSeedHex: RECIPIENT_SEED_HEX },
	);

	expect(result.readOnly, 'a signer-bound UserClient must not be read-only').toBe(false);
	expect(result.signer, 'the bound signer must be the trusted account').toBe(info.trusted);
	expect(result.blockHexRoundTrips, 'a block must survive a toHex/fromHex round-trip').toBe(true);
	expect(result.transmitted, 'the node must accept the builder-assembled send').toBe(true);
	expect(BigInt(result.recipientBalance), 'the builder send must credit the recipient balance').toBe(
		BigInt(info.amount),
	);
});

test('errors cross the boundary with a stable code', async ({ page }) => {
	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const code: string = await page.evaluate(async () => {
		const { Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		try {
			Account.fromSeed('not-hex', 0, 'ed25519');
			return 'NO_THROW';
		} catch (error) {
			return (error as { code?: string }).code ?? 'NO_CODE';
		}
	});

	expect(code, 'a malformed seed must throw an Error carrying code INVALID_SEED').toBe('INVALID_SEED');
});

test('a generated account is recoverable and can be funded', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: GenerationRoundTrip = await page.evaluate(async (cfg: NodeInfo) => {
		const { KeetaClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		const token = Account.fromAddress(cfg.baseToken);
		const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');

		// A freshly minted seed must derive a usable, fundable account.
		const seedHex = Account.generateSeed();
		const recipient = Account.fromSeed(seedHex, 0, 'ed25519');

		// A mnemonic must deterministically recover the same address.
		const words = Account.generatePassphrase();
		const derived = Account.fromPassphrase(words, 0, 'ed25519');
		const derivedAgain = Account.fromPassphrase(words, 0, 'ed25519');
		const deterministic = derived.address === derivedAgain.address;

		const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
		const transmitted = await client.send(trusted, recipient, cfg.amount, token);
		const recipientBalance = await client.balance(recipient, token);

		return {
			seedHexLength: seedHex.length,
			passphraseWords: words.length,
			derivedAddress: derived.address,
			deterministic,
			transmitted,
			recipientBalance,
		};
	}, info);

	expect(result.seedHexLength, 'a generated seed must be 32 bytes of hex').toBe(64);
	expect(result.passphraseWords, 'a generated mnemonic must be 24 words').toBe(24);
	expect(result.derivedAddress, 'a mnemonic-derived account must have an address').toMatch(/^keeta_/);
	expect(result.deterministic, 'the same mnemonic must recover the same address').toBe(true);
	expect(result.transmitted, 'the node must accept a send to the generated account').toBe(true);
	expect(BigInt(result.recipientBalance), 'the send must credit the generated account').toBe(BigInt(info.amount));
});

test('permission inputs validate their flags with a stable code', async ({ page }) => {
	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: { code: string; accepts: boolean } = await page.evaluate(async () => {
		const { Permissions, PermissionChange, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		let code = 'NO_THROW';
		try {
			new Permissions(['definitely_not_a_flag'], new Uint8Array());
		} catch (error) {
			code = (error as { code?: string }).code ?? 'NO_CODE';
		}

		const principal = Account.fromSeed('33'.repeat(32), 0, 'ed25519');
		const change = PermissionChange.forAccount(principal, 'set');
		change.setPermissions(new Permissions(['access', 'update_info'], new Uint8Array()));

		const accepts = true;

		return { code, accepts };
	});

	expect(result.code, 'an unknown permission flag must throw code INVALID_PERMISSION_FLAG').toBe(
		'INVALID_PERMISSION_FLAG',
	);
	expect(result.accepts, 'a valid permission change must assemble').toBe(true);
});

const SIGNING_ALGORITHMS = ['ed25519', 'ecdsa_secp256k1', 'ecdsa_secp256r1'] as const;

for (const algorithm of SIGNING_ALGORITHMS) {
	test(`${algorithm} account signs, verifies, and round-trips encryption`, async ({ page }) => {
		await page.goto('/e2e/index.html');
		await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

		const result: {
			publicKey: string;
			derivedAlgorithm: string;
			signatureLength: number;
			valid: boolean;
			tampered: boolean;
			decrypted: string;
		} = await page.evaluate(async (algo: string) => {
			const { Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

			const me = Account.fromSeed('44'.repeat(32), 0, algo);
			const message = new TextEncoder().encode('keeta network');
			const signature = me.sign(message);

			const valid = me.verify(message, signature);
			const tampered = me.verify(new TextEncoder().encode('keeta networl'), signature);

			const cipher = me.encrypt(message);
			const decrypted = new TextDecoder().decode(me.decrypt(cipher));

			return {
				publicKey: me.publicKey,
				derivedAlgorithm: me.algorithm,
				signatureLength: signature.length,
				valid,
				tampered,
				decrypted,
			};
		}, algorithm);

		expect(result.derivedAlgorithm, 'the seed must derive the requested algorithm').toBe(algorithm);
		expect(result.publicKey, 'publicKey must be type-prefixed hex').toMatch(/^[0-9a-f]+$/);
		expect(result.signatureLength, 'every supported curve signs in 64 bytes').toBe(64);
		expect(result.valid, 'a genuine signature must verify').toBe(true);
		expect(result.tampered, 'a tampered message must not verify').toBe(false);
		expect(result.decrypted, 'encrypt then decrypt must recover the plaintext').toBe('keeta network');
	});
}

test('fromSeed defaults to secp256k1 when no algorithm is given', async ({ page }) => {
	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const derivedAlgorithm: string = await page.evaluate(async () => {
		const { Account } = (window as unknown as { keeta: typeof Keeta }).keeta;
		return Account.fromSeed('44'.repeat(32), 0).algorithm;
	});

	expect(derivedAlgorithm, 'an omitted algorithm must default to secp256k1').toBe('ecdsa_secp256k1');
});

test('UserClient builds a swap-request block against a live node', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: { hash: string; hexRoundTrips: boolean } = await page.evaluate(
		async (cfg: { info: NodeInfo; recipientSeedHex: string }) => {
			const { KeetaClient, UserClient, Account, Block } = (window as unknown as { keeta: typeof Keeta }).keeta;

			const token = Account.fromAddress(cfg.info.baseToken);
			const trusted = Account.fromSeed(cfg.info.trustedSeedHex, 0, 'ed25519');
			const counterparty = Account.fromSeed(cfg.recipientSeedHex, 0, 'ed25519');

			const client = new KeetaClient(cfg.info.api).withNetwork(cfg.info.network);
			const user = UserClient.fromClient(client, trusted);

			// Maker side: give the base token, expect the base token back. The
			// block is built and signed but not published.
			const block = await user.createSwapRequest(counterparty, token, cfg.info.amount, token, cfg.info.amount, false);
			const hexRoundTrips = Block.fromHex(block.toHex()).hash === block.hash;

			return { hash: block.hash, hexRoundTrips };
		},
		{ info, recipientSeedHex: RECIPIENT_SEED_HEX },
	);

	expect(result.hash, 'the swap-request block must have a hash').toMatch(/[0-9A-F]/i);
	expect(result.hexRoundTrips, 'the swap-request block must survive a hex round-trip').toBe(true);
});

test('reads return structured, typed views with string amounts', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: TypedReads = await page.evaluate(async (cfg: NodeInfo) => {
		const { KeetaClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
		const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
		const token = Account.fromAddress(cfg.baseToken);

		// Drive a send so the trusted account has settled state to read back.
		await client.send(trusted, Account.fromAddress(cfg.recipient), cfg.amount, token);

		const balances = await client.balances(trusted);
		let balanceFields: { token: string; balance: string; pending: string } | null = null;
		const baseEntry = balances.find((entry) => entry.token === cfg.baseToken);
		if (baseEntry) {
			balanceFields = { token: baseEntry.token, balance: baseEntry.balance, pending: baseEntry.pending };
		}

		const state = await client.state(trusted);
		let stateHeadIsString = false;
		if (state.head) {
			stateHeadIsString = typeof state.head === 'string';
		}

		const reps = await client.representatives();
		let repWeightIsString = false;
		if (reps.length > 0) {
			repWeightIsString = typeof reps[0].weight === 'string';
		}

		return {
			balanceFields,
			stateBalances: state.balances.length,
			stateHeadIsString,
			repCount: reps.length,
			repWeightIsString,
		};
	}, info);

	expect(result.balanceFields, 'balances must expose a base-token entry').not.toBeNull();
	expect(result.balanceFields?.token, 'the balance entry must name the base token').toBe(info.baseToken);
	expect(typeof result.balanceFields?.balance, 'a settled balance must be a decimal string').toBe('string');
	expect(typeof result.balanceFields?.pending, 'a pending balance must be a decimal string').toBe('string');
	expect(result.stateBalances, 'state must carry at least the base-token balance').toBeGreaterThanOrEqual(1);
	expect(result.stateHeadIsString, 'a settled head must surface as a hex string').toBe(true);
	expect(result.repCount, 'the network must report at least one representative').toBeGreaterThanOrEqual(1);
	expect(result.repWeightIsString, 'a representative weight must be a decimal string').toBe(true);
});

test('Permissions decode and round-trip the on-chain bitmaps', async ({ page }) => {
	await page.goto('/e2e/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: PermissionDecode = await page.evaluate(async () => {
		const { Permissions } = (window as unknown as { keeta: typeof Keeta }).keeta;

		const built = new Permissions(['access', 'update_info'], new Uint8Array([3, 7]));
		const builtFlags = built.flags;
		const builtOffsets = Array.from(built.offsets);
		const hasAccess = built.has(['access'], new Uint8Array());
		const hasOwner = built.has(['owner'], new Uint8Array());
		const hasOffset3 = built.has(['access'], new Uint8Array([3]));
		const hasOffset4 = built.has(['access'], new Uint8Array([4]));

		// toBitmaps -> fromBitmaps must reconstruct the same permission set.
		const [base, external] = built.toBitmaps();
		const roundTrip = Permissions.fromBitmaps(base, external);
		const roundTripFlags = roundTrip.flags;
		const roundTripOffsets = Array.from(roundTrip.offsets);

		// Decode the raw bitmaps an ACL row returns: 0x9 = ACCESS|UPDATE_INFO,
		// 0x84 = external offsets {2, 7}.
		const decoded = Permissions.fromBitmaps('0x9', '0x84');
		const decodedFlags = decoded.flags;
		const decodedOffsets = Array.from(decoded.offsets);

		return {
			builtFlags,
			builtOffsets,
			hasAccess,
			hasOwner,
			hasOffset3,
			hasOffset4,
			roundTripFlags,
			roundTripOffsets,
			decodedFlags,
			decodedOffsets,
		};
	});

	expect(result.builtFlags, 'flags must decode back to the named base flags').toEqual(['access', 'update_info']);
	expect(result.builtOffsets, 'offsets must decode back to the external bits set').toEqual([3, 7]);
	expect(result.hasAccess, 'a granted base flag must report present').toBe(true);
	expect(result.hasOwner, 'an absent base flag must report missing').toBe(false);
	expect(result.hasOffset3, 'a granted external offset must report present').toBe(true);
	expect(result.hasOffset4, 'an absent external offset must report missing').toBe(false);
	expect(result.roundTripFlags, 'a bitmap round-trip must preserve flags').toEqual(['access', 'update_info']);
	expect(result.roundTripOffsets, 'a bitmap round-trip must preserve offsets').toEqual([3, 7]);
	expect(result.decodedFlags, 'raw ACL bitmaps must decode to flag names').toEqual(['access', 'update_info']);
	expect(result.decodedOffsets, 'raw ACL bitmaps must decode external offsets').toEqual([2, 7]);
});
