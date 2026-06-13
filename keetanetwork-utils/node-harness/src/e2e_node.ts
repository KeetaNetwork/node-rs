/*
 * End-to-end harness: runs a live local reference node (in-memory
 * ledger) and exposes it over a JSON-lines protocol on stdin/stdout.
 *
 * Usage: node dist/e2e_node.js <path-to-node-dist>
 *
 * Commands:
 *   { cmd: "init_supply", amount }            mint initial supply to the trusted account
 *   { cmd: "send", to, amount, external? }    send base token from the trusted account
 *   { cmd: "set_info", name, description, metadata }
 *   { cmd: "manage_cert_add" }                add a freshly minted certificate to the trusted account
 *   { cmd: "head", account }                  head hash + base token balance for an account
 *   { cmd: "transmit", bytes }                publish externally built block bytes to the node
 *   { cmd: "shutdown" }                       stop the node and exit
 */

import * as readline from 'node:readline';

import type * as ClientModule from '@keetanetwork/keetanet-node/dist/client/index';
import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';
import type * as CertificateModule from '@keetanetwork/keetanet-node/dist/lib/utils/certificate';
import type * as HelperTestingModule from '@keetanetwork/keetanet-node/dist/lib/utils/helper_testing';
import type { Block as BlockInstance } from '@keetanetwork/keetanet-node/dist/lib/block/index';

import { loadModule, resolveDist } from './dist';

const dist = resolveDist(process.argv[2], 'usage: e2e_node.js <path-to-node-dist>');

const { UserClient } = loadModule<typeof ClientModule>(dist, 'client/index.js');
const { createTestNode } = loadModule<typeof HelperTestingModule>(dist, 'lib/utils/helper_testing.js');
const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { Block, AdjustMethod } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');
const { CertificateBuilder } = loadModule<typeof CertificateModule>(dist, 'lib/utils/certificate.js');

/* Deterministic harness accounts; the "rust" side derives its own keys */
const REP_SEED = Buffer.alloc(32, 0x5a).toString('hex');
const TRUSTED_SEED = Buffer.alloc(32, 0x77).toString('hex');

interface InitSupplyRequest {
	cmd: 'init_supply';
	amount: string;
}

interface SendRequest {
	cmd: 'send';
	to: string;
	amount: string;
	external?: string;
}

interface SetInfoRequest {
	cmd: 'set_info';
	name: string;
	description: string;
	metadata: string;
}

interface ManageCertAddRequest {
	cmd: 'manage_cert_add';
}

interface HeadRequest {
	cmd: 'head';
	account: string;
}

interface TransmitRequest {
	cmd: 'transmit';
	bytes: string;
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type HarnessRequest =
	InitSupplyRequest |
	SendRequest |
	SetInfoRequest |
	ManageCertAddRequest |
	HeadRequest |
	TransmitRequest |
	ShutdownRequest;

interface DirectResult {
	voteStaple: {
		blocks: BlockInstance[];
	};
}

interface PublishAidResult {
	blocks: BlockInstance[];
}

function stapleBlocks(result: DirectResult | PublishAidResult): { bytes: string; hash: string }[] {
	let blocks: BlockInstance[];
	if ('voteStaple' in result) {
		blocks = result.voteStaple.blocks;
	} else {
		blocks = result.blocks;
	}

	return(blocks.map(function(block) {
		return({
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase(),
			hash: block.hash.toString()
		});
	}));
}

async function main(): Promise<void> {
	const repKey = Account.fromSeed(REP_SEED, 0, AccountKeyAlgorithm.ED25519);
	const trustedKey = Account.fromSeed(TRUSTED_SEED, 0, AccountKeyAlgorithm.ED25519);

	const node = await createTestNode(repKey, {
		initialTrustedAccount: trustedKey
	});

	const nodeOptions = node.config.nodeOptions;
	if (nodeOptions === undefined) {
		throw(new Error('test node did not report listen options'));
	}

	const ip = nodeOptions.listenIP;
	const port = nodeOptions.listenPort;

	const trustedClient = UserClient.fromSimpleSingleRep(
		`${ip}:${port}`,
		false,
		repKey,
		node.config.network,
		node.config.networkAlias,
		trustedKey
	);

	async function handleRequest(request: HarnessRequest): Promise<{ [key: string]: unknown }> {
		switch (request.cmd) {
			case 'init_supply': {
				const result = await trustedClient.initializeNetwork({
					addSupplyAmount: BigInt(request.amount)
				});
				return({ event: 'initialized', blocks: stapleBlocks(result) });
			}

			case 'send': {
				const to = Account.fromPublicKeyString(request.to);
				const result = await trustedClient.send(to, BigInt(request.amount), node.baseToken, request.external);
				return({ event: 'sent', blocks: stapleBlocks(result) });
			}

			case 'set_info': {
				const result = await trustedClient.setInfo({
					name: request.name,
					description: request.description,
					metadata: request.metadata
				});
				return({ event: 'info_set', blocks: stapleBlocks(result) });
			}

			case 'manage_cert_add': {
				const certificate = await new CertificateBuilder({
					issuer: trustedKey,
					validFrom: new Date(Date.now() - (60 * 60 * 1000)),
					validTo: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000))
				}).build({
					serial: 7,
					subjectPublicKey: trustedKey
				});

				const result = await trustedClient.modifyCertificate(AdjustMethod.ADD, certificate, null);
				return({ event: 'certificate_added', blocks: stapleBlocks(result) });
			}

			case 'head': {
				const account = Account.fromPublicKeyString(request.account);
				const head = await trustedClient.client.getHeadBlock(account);
				const balance = await trustedClient.client.getBalance(account, node.baseToken);

				let headHash: string | null = null;
				if (head !== null) {
					headHash = head.hash.toString();
				}

				return({ event: 'head', head: headHash, balance: balance.toString() });
			}

			case 'transmit': {
				const buffer = Buffer.from(request.bytes, 'hex');
				const arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
				const block = new Block(arrayBuffer);

				const result = await trustedClient.client.transmit([block]);
				return({ event: 'transmitted', blocks: stapleBlocks(result), hash: block.hash.toString() });
			}

			case 'shutdown': {
				setImmediate(async function() {
					try {
						await trustedClient.client.destroy();
						await trustedClient.destroy();
						await node.stop();
					} finally {
						process.exit(0);
					}
				});
				return({ event: 'shutdown' });
			}

			default: {
				throw(new Error(`Unknown command: ${JSON.stringify(request)}`));
			}
		}
	}

	console.log(JSON.stringify({
		event: 'ready',
		network: node.config.network.toString(),
		networkAlias: node.config.networkAlias,
		baseToken: node.baseToken.publicKeyString.get(),
		trusted: trustedKey.publicKeyString.get(),
		representative: repKey.publicKeyString.get()
	}));

	const rl = readline.createInterface({ input: process.stdin, terminal: false });

	/* Serialize command handling: one response line per request line */
	let queue = Promise.resolve();
	rl.on('line', function(line) {
		if (line.trim() === '') {
			return;
		}

		queue = queue.then(async function() {
			try {
				/* Protocol lines are produced by the trusted Rust test driver */
				// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
				const request = JSON.parse(line) as HarnessRequest;
				const response = await handleRequest(request);
				console.log(JSON.stringify(response));
			} catch (error) {
				console.error(error);

				let message = String(error);
				if (error instanceof Error) {
					message = error.message;
				}

				console.log(JSON.stringify({ error: message }));
			}
		});
	});
}

main().catch(function(error: unknown) {
	console.error(error);
	process.exit(1);
});
