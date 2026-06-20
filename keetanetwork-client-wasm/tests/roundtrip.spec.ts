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
	balanceFields: { token: string; balance: string } | null;
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

// A recipient reserved for the external-data send so its credited balance is
// the sole consequence of that one transfer.
const EXTERNAL_RECIPIENT_SEED_HEX = '55'.repeat(32);

async function loadNodeInfo(request: {
	get: (url: string) => Promise<{ json: () => Promise<NodeInfo> }>;
}): Promise<NodeInfo> {
	const response = await request.get('/node-info.json');
	return response.json();
}

test('KeetaClient publishes a send round-trip against a live node', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/tests/index.html');
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

	await page.goto('/tests/index.html');
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
	await page.goto('/tests/index.html');
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

	await page.goto('/tests/index.html');
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
	await page.goto('/tests/index.html');
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
		await page.goto('/tests/index.html');
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
	await page.goto('/tests/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const derivedAlgorithm: string = await page.evaluate(async () => {
		const { Account } = (window as unknown as { keeta: typeof Keeta }).keeta;
		return Account.fromSeed('44'.repeat(32), 0).algorithm;
	});

	expect(derivedAlgorithm, 'an omitted algorithm must default to secp256k1').toBe('ecdsa_secp256k1');
});

test('UserClient builds a swap-request block against a live node', async ({ page }) => {
	const info = await loadNodeInfo(page.request);

	await page.goto('/tests/index.html');
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

	await page.goto('/tests/index.html');
	await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);

	const result: TypedReads = await page.evaluate(async (cfg: NodeInfo) => {
		const { KeetaClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

		const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
		const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
		const token = Account.fromAddress(cfg.baseToken);

		// Drive a send so the trusted account has settled state to read back.
		await client.send(trusted, Account.fromAddress(cfg.recipient), cfg.amount, token);

		const balances = await client.balances(trusted);
		let balanceFields: { token: string; balance: string } | null = null;
		const baseEntry = balances.find((entry) => entry.token === cfg.baseToken);
		if (baseEntry) {
			balanceFields = { token: baseEntry.token, balance: baseEntry.balance };
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
	expect(result.stateBalances, 'state must carry at least the base-token balance').toBeGreaterThanOrEqual(1);
	expect(result.stateHeadIsString, 'a settled head must surface as a hex string').toBe(true);
	expect(result.repCount, 'the network must report at least one representative').toBeGreaterThanOrEqual(1);
	expect(result.repWeightIsString, 'a representative weight must be a decimal string').toBe(true);
});

test('Permissions decode and round-trip the on-chain bitmaps', async ({ page }) => {
	await page.goto('/tests/index.html');
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

test.describe('extended client and user surface', () => {
	let info: NodeInfo;

	test.beforeEach(async ({ page }) => {
		info = await loadNodeInfo(page.request);
		await page.goto('/tests/index.html');
		await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);
	});

	test('account state surfaces the name, description, and metadata set via setInfo', async ({ page }) => {
		const result: { name?: string; description?: string; metadata?: string } | undefined = await page.evaluate(
			async (cfg: NodeInfo) => {
				const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

				const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
				const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
				const user = UserClient.fromClient(client, trusted);

				await user.setInfo('WASMTREASURY', 'the wasm treasury account', 'tier-genesis');

				const state = await user.state();
				return state.info;
			},
			info,
		);

		expect(result?.name, 'state.info must echo the name set via setInfo').toBe('WASMTREASURY');
		expect(result?.description, 'state.info must echo the description set via setInfo').toBe(
			'the wasm treasury account',
		);
		expect(result?.metadata, 'state.info must echo the metadata set via setInfo').toBe('tier-genesis');
	});

	const SUPPLY_ADJUSTMENTS = [
		{ method: 'add', sign: 1n },
		{ method: 'subtract', sign: -1n },
	] as const;

	for (const { method, sign } of SUPPLY_ADJUSTMENTS) {
		test(`modifyTokenSupplyAndBalance "${method}" moves the named token's total supply`, async ({ page }) => {
			const result: { accepted: boolean; before: string; after: string } = await page.evaluate(
				async (cfg: NodeInfo & { method: string }) => {
					const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

					const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
					const token = Account.fromAddress(cfg.baseToken);
					const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
					const user = UserClient.fromClient(client, trusted);

					const before = await client.tokenSupply(token);
					const accepted = await user.modifyTokenSupplyAndBalance(token, cfg.amount, cfg.method, trusted);
					const after = await client.tokenSupply(token);

					return { accepted, before: before ?? '', after: after ?? '' };
				},
				{ ...info, method },
			);

			expect(result.accepted, 'the node must accept the supply-and-balance staple').toBe(true);
			expect(BigInt(result.after) - BigInt(result.before), `a "${method}" must shift supply by the amount`).toBe(
				sign * BigInt(info.amount),
			);
		});
	}

	test('a UserClient pages its own chain and history', async ({ page }) => {
		const result: { pageCount: number; allCount: number; historyCount: number; firstStapleIsHex: boolean } =
			await page.evaluate(async (cfg: NodeInfo) => {
				const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

				const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
				const token = Account.fromAddress(cfg.baseToken);
				const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
				const user = UserClient.fromClient(client, trusted);

				await user.send(Account.fromAddress(cfg.recipient), cfg.amount, token);

				const firstPage = await user.chainPage(undefined, undefined, 1);
				const everyBlock = await user.chainAll(50);
				const history = await user.historyPage(undefined, 50);

				return {
					pageCount: firstPage.length,
					allCount: everyBlock.length,
					historyCount: history.length,
					firstStapleIsHex: /^[0-9a-f]+$/.test(history[0]?.staple ?? ''),
				};
			}, info);

		expect(result.allCount, 'chainAll must return the account chain').toBeGreaterThanOrEqual(1);
		expect(result.pageCount, 'a one-block page must return at least one block').toBeGreaterThanOrEqual(1);
		expect(result.pageCount, 'a bounded page must not exceed the full chain').toBeLessThanOrEqual(result.allCount);
		expect(result.historyCount, 'historyPage must return at least one entry').toBeGreaterThanOrEqual(1);
		expect(result.firstStapleIsHex, 'a history entry must carry its staple as hex').toBe(true);
	});

	test('a certificate lookup by an unknown hash resolves to nothing', async ({ page }) => {
		const result: { missing: boolean; listed: boolean } = await page.evaluate(async (cfg: NodeInfo) => {
			const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

			const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
			const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
			const user = UserClient.fromClient(client, trusted);

			const found = await user.certificate('00'.repeat(32));
			const all = await user.certificates();

			return { missing: found === undefined || found === null, listed: Array.isArray(all) };
		}, info);

		expect(result.missing, 'an unknown certificate hash must resolve to nothing').toBe(true);
		expect(result.listed, 'certificates must return a list').toBe(true);
	});

	test('sendExternal transfers and credits the recipient', async ({ page }) => {
		const result: { accepted: boolean; balance: string } = await page.evaluate(
			async (cfg: NodeInfo & { externalRecipientSeedHex: string }) => {
				const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

				const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
				const recipient = Account.fromSeed(cfg.externalRecipientSeedHex, 0, 'ed25519');
				const token = Account.fromAddress(cfg.baseToken);
				const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
				const user = UserClient.fromClient(client, trusted);

				const accepted = await user.sendExternal(recipient, cfg.amount, token, 'invoice-42');
				const balance = await client.balance(recipient, token);

				return { accepted, balance };
			},
			{ ...info, externalRecipientSeedHex: EXTERNAL_RECIPIENT_SEED_HEX },
		);

		expect(result.accepted, 'the node must accept the external-data send').toBe(true);
		expect(BigInt(result.balance), 'the external-data send must credit the recipient').toBe(BigInt(info.amount));
	});

	test('getBlock reads the main ledger by hash and rejects an unknown side', async ({ page }) => {
		const result: {
			headHash: string;
			mainHash: string | null;
			defaultHash: string | null;
			sideIsEmpty: boolean;
			invalidCode: string;
		} = await page.evaluate(async (cfg: NodeInfo) => {
			const { KeetaClient, UserClient, Account } = (window as unknown as { keeta: typeof Keeta }).keeta;

			const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
			const token = Account.fromAddress(cfg.baseToken);
			const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
			const user = UserClient.fromClient(client, trusted);

			await user.send(Account.fromAddress(cfg.recipient), cfg.amount, token);

			const head = await user.head();
			const headHash = head?.hash ?? '';
			const onMain = await client.block(headHash, 'main');
			const onDefault = await client.block(headHash, undefined);
			const onSide = await client.block(headHash, 'side');

			let invalidCode = 'NO_THROW';
			try {
				await client.block(headHash, 'galaxy');
			} catch (error) {
				invalidCode = (error as { code?: string }).code ?? 'NO_CODE';
			}

			return {
				headHash,
				mainHash: onMain?.hash ?? null,
				defaultHash: onDefault?.hash ?? null,
				sideIsEmpty: onSide === undefined || onSide === null,
				invalidCode,
			};
		}, info);

		expect(result.mainHash, 'the settled head must resolve on the main ledger').toBe(result.headHash);
		expect(result.defaultHash, 'an omitted side must default to the main ledger').toBe(result.headHash);
		expect(result.sideIsEmpty, 'a settled head must not appear on the side ledger').toBe(true);
		expect(result.invalidCode, 'an unknown side must throw code INVALID_LEDGER_SIDE').toBe('INVALID_LEDGER_SIDE');
	});

	const RECOVER_VARIANTS = ['default', 'options'] as const;

	for (const variant of RECOVER_VARIANTS) {
		test(`recover finds nothing to recover for a healthy account (${variant})`, async ({ page }) => {
			const result: { recovered: boolean } = await page.evaluate(
				async (cfg: NodeInfo & { variant: string }) => {
					const { KeetaClient, UserClient, Account, TransmitOptions } = (
						window as unknown as { keeta: typeof Keeta }
					).keeta;

					const trusted = Account.fromSeed(cfg.trustedSeedHex, 0, 'ed25519');
					const client = new KeetaClient(cfg.api).withNetwork(cfg.network);
					const user = UserClient.fromClient(client, trusted);

					const optionsByVariant: Record<string, InstanceType<typeof TransmitOptions> | undefined> = {
						default: undefined,
						options: new TransmitOptions(),
					};

					const staple = await user.recover(false, optionsByVariant[cfg.variant]);
					return { recovered: staple === undefined || staple === null };
				},
				{ ...info, variant },
			);

			expect(result.recovered, 'a healthy account must have nothing to recover').toBe(true);
		});
	}

	test('a representative endpoint accepts a bigint-string weight and rejects a non-numeric one', async ({ page }) => {
		const result: { version: string; invalidCode: string } = await page.evaluate(async (cfg: NodeInfo) => {
			const { KeetaClient, Account, RepEndpoint } = (window as unknown as { keeta: typeof Keeta }).keeta;

			const discovery = new KeetaClient(cfg.api).withNetwork(cfg.network);
			const rep = await discovery.nodeRepresentative();
			const repAccount = Account.fromAddress(rep.account);

			const endpoint = new RepEndpoint(cfg.api, repAccount, '7');
			const client = KeetaClient.forRepresentatives([endpoint]).withNetwork(cfg.network);
			const version = await client.nodeVersion();

			let invalidCode = 'NO_THROW';
			try {
				new RepEndpoint(cfg.api, repAccount, 'not-a-number');
			} catch (error) {
				invalidCode = (error as { code?: string }).code ?? 'NO_CODE';
			}

			return { version, invalidCode };
		}, info);

		expect(result.version, 'a string-weighted representative must yield a working client').not.toBe('');
		expect(result.invalidCode, 'a non-numeric weight must throw code INVALID_WEIGHT').toBe('INVALID_WEIGHT');
	});
});
