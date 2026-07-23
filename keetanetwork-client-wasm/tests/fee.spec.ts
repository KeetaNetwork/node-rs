// Fee payment surface against a fee-enforcing node (the second webServer in
// playwright.config.ts): the votes on every staple demand a flat base-token
// fee, so each probe exercises a real FEE_REQUIRED round.

import { expect, test } from '@playwright/test';

import type * as Keeta from '../pkg/keetanetwork_client_wasm';
import { FEE_PORT } from './playwright.config';

const FEE_BASE = `http://localhost:${FEE_PORT}`;

interface NodeInfo {
	api: string;
	network: string;
	baseToken: string;
	trusted: string;
	recipient: string;
	trustedSeedHex: string;
	amount: string;
	fee: string;
}

// One recipient per crediting probe so each credited balance is the sole
// consequence of that probe's transfer.
const SIGNER_RECIPIENT_SEED_HEX = '81'.repeat(32);
const FACTORY_RECIPIENT_SEED_HEX = '82'.repeat(32);

// The third party that pays the fee in the custom-factory probe.
const PAYER_SEED_HEX = '83'.repeat(32);

// The probes whose transmit must fail with a typed code. Each gets its own
// funded sender so its abandoned temporary vote cannot collide with the
// trusted account's later staples.
const FAILING_PROBES = [
	{ reason: 'a required fee without a factory', code: 'FEE_REQUIRED', senderSeedHex: '84'.repeat(32) },
	{ reason: 'a throwing factory', code: 'FEE_BLOCK_FACTORY', senderSeedHex: '85'.repeat(32) },
] as const;

test.describe('fee payment surface', () => {
	let info: NodeInfo;

	test.beforeEach(async ({ page }) => {
		const response = await page.request.get(`${FEE_BASE}/node-info.json`);
		info = (await response.json()) as NodeInfo;
		await page.goto(`${FEE_BASE}/tests/index.html`);
		await page.waitForFunction(() => (window as unknown as { wasmReady?: boolean }).wasmReady === true);
	});

	test('setFeeSigner pays the required fee from the sender', async ({ page }) => {
		const result: { transmitted: boolean; senderDebit: string; recipientBalance: string } = await page.evaluate(
			async (cfg: { info: NodeInfo; recipientSeedHex: string }) => {
				const { KeetaClient, UserClient, Account, TransmitOptions } = (
					window as unknown as { keeta: typeof Keeta }
				).keeta;

				const client = new KeetaClient(cfg.info.api).withNetwork(cfg.info.network);
				const trusted = Account.fromSeed(cfg.info.trustedSeedHex, 0, 'ed25519');
				const recipient = Account.fromSeed(cfg.recipientSeedHex, 0, 'ed25519');
				const token = Account.fromPublicKeyString(cfg.info.baseToken);
				const user = UserClient.fromClient(client, trusted);

				const before = await client.balance(trusted, token);

				const builder = user.initBuilder();
				builder.send(recipient, cfg.info.amount, token);
				const blocks = await builder.build();

				const options = new TransmitOptions();
				options.setFeeSigner(trusted);
				const transmitted = await user.transmit(blocks, options);

				const after = await client.balance(trusted, token);
				const recipientBalance = await client.balance(recipient, token);

				return {
					transmitted,
					senderDebit: (BigInt(before) - BigInt(after)).toString(),
					recipientBalance,
				};
			},
			{ info, recipientSeedHex: SIGNER_RECIPIENT_SEED_HEX },
		);

		expect(result.transmitted, 'the fee-enforcing node must accept the fee-paying staple').toBe(true);
		expect(BigInt(result.senderDebit), 'the sender must be debited the amount plus the fee').toBe(
			BigInt(info.amount) + BigInt(info.fee),
		);
		expect(BigInt(result.recipientBalance), 'the recipient must be credited the amount alone').toBe(
			BigInt(info.amount),
		);
	});

	test('setGenerateFeeBlock routes the fee to a third-party payer via buildFeeBlock', async ({ page }) => {
		const result: {
			transmitted: boolean;
			senderDebit: string;
			payerDebit: string;
			recipientBalance: string;
		} = await page.evaluate(
			async (cfg: { info: NodeInfo; recipientSeedHex: string; payerSeedHex: string; payerFund: string }) => {
				const { KeetaClient, UserClient, Account, TransmitOptions } = (
					window as unknown as { keeta: typeof Keeta }
				).keeta;

				const client = new KeetaClient(cfg.info.api).withNetwork(cfg.info.network);
				const trusted = Account.fromSeed(cfg.info.trustedSeedHex, 0, 'ed25519');
				const recipient = Account.fromSeed(cfg.recipientSeedHex, 0, 'ed25519');
				const payer = Account.fromSeed(cfg.payerSeedHex, 0, 'ed25519');
				const token = Account.fromPublicKeyString(cfg.info.baseToken);
				const user = UserClient.fromClient(client, trusted);

				// The payer needs base-token funds to cover the fee it will send.
				await client.send(trusted, payer, cfg.payerFund, token);

				const senderBefore = await client.balance(trusted, token);
				const payerBefore = await client.balance(payer, token);

				const builder = user.initBuilder();
				builder.send(recipient, cfg.info.amount, token);
				const blocks = await builder.build();

				const options = new TransmitOptions();
				options.setGenerateFeeBlock(
					(factoryClient: Keeta.KeetaClient, staple: Keeta.VoteStaple, priority: Keeta.Account[]) =>
						factoryClient.buildFeeBlock(staple, payer, payer, priority),
				);
				const transmitted = await user.transmit(blocks, options);

				const senderAfter = await client.balance(trusted, token);
				const payerAfter = await client.balance(payer, token);
				const recipientBalance = await client.balance(recipient, token);

				return {
					transmitted,
					senderDebit: (BigInt(senderBefore) - BigInt(senderAfter)).toString(),
					payerDebit: (BigInt(payerBefore) - BigInt(payerAfter)).toString(),
					recipientBalance,
				};
			},
			{ info, recipientSeedHex: FACTORY_RECIPIENT_SEED_HEX, payerSeedHex: PAYER_SEED_HEX, payerFund: '500' },
		);

		expect(result.transmitted, 'the fee-enforcing node must accept the factory-fee staple').toBe(true);
		expect(BigInt(result.senderDebit), 'the sender must be debited the amount alone').toBe(BigInt(info.amount));
		expect(BigInt(result.payerDebit), 'the third-party payer must be debited exactly the fee').toBe(
			BigInt(info.fee),
		);
		expect(BigInt(result.recipientBalance), 'the recipient must be credited the amount alone').toBe(
			BigInt(info.amount),
		);
	});

	for (const probe of FAILING_PROBES) {
		test(`${probe.reason} throws code ${probe.code}`, async ({ page }) => {
			const code: string = await page.evaluate(
				async (cfg: { info: NodeInfo; senderSeedHex: string; senderFund: string; code: string }) => {
					const { KeetaClient, UserClient, Account, TransmitOptions } = (
						window as unknown as { keeta: typeof Keeta }
					).keeta;

					const client = new KeetaClient(cfg.info.api).withNetwork(cfg.info.network);
					const trusted = Account.fromSeed(cfg.info.trustedSeedHex, 0, 'ed25519');
					const sender = Account.fromSeed(cfg.senderSeedHex, 0, 'ed25519');
					const token = Account.fromPublicKeyString(cfg.info.baseToken);

					await client.send(trusted, sender, cfg.senderFund, token);
					const user = UserClient.fromClient(client, sender);

					const builder = user.initBuilder();
					builder.send(trusted, cfg.info.amount, token);
					const blocks = await builder.build();

					// One transmitter per expected code. FEE_REQUIRED goes through
					// the bare KeetaClient: a signer-bound UserClient defaults to
					// paying its own fee, so the no-factory path never surfaces there.
					const throwingFactory = new TransmitOptions();
					throwingFactory.setGenerateFeeBlock(async () => {
						throw new Error('payer offline');
					});
					const transmitByCode: Record<string, () => Promise<boolean>> = {
						FEE_REQUIRED: () => client.transmit(blocks, new TransmitOptions()),
						FEE_BLOCK_FACTORY: () => user.transmit(blocks, throwingFactory),
					};

					try {
						await transmitByCode[cfg.code]();
						return 'NO_THROW';
					} catch (error) {
						return (error as { code?: string }).code ?? 'NO_CODE';
					}
				},
				{ info, senderSeedHex: probe.senderSeedHex, senderFund: '2000', code: probe.code },
			);

			expect(code, `${probe.reason} must throw code ${probe.code}`).toBe(probe.code);
		});
	}
});
