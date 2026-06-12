#!/usr/bin/env node
'use strict';

/*
 * End-to-end harness: runs a live local reference node (in-memory
 * ledger) and exposes it over a JSON-lines protocol on stdin/stdout.
 *
 * Usage: node e2e_node.cjs <path-to-keetanet-node-dist>
 *
 * Every request line receives exactly one response line. Committed
 * blocks are always reported as { bytes, hash } with uppercase hex
 * wire bytes. Diagnostics go to stderr.
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

const path = require('path');
const readline = require('readline');

if (process.argv[2] === undefined) {
	console.error('Usage: node e2e_node.cjs <path-to-keetanet-node-dist>');
	process.exit(2);
}

const distSrc = path.resolve(process.argv[2]);

const { UserClient } = require(path.join(distSrc, 'client/index.js'));
const { createTestNode } = require(path.join(distSrc, 'lib/utils/helper_testing.js'));
const { Account, AccountKeyAlgorithm } = require(path.join(distSrc, 'lib/account.js'));
const { Block, AdjustMethod } = require(path.join(distSrc, 'lib/block/index.js'));
const { CertificateBuilder } = require(path.join(distSrc, 'lib/utils/certificate.js'));

/* Deterministic harness accounts; the "rust" side derives its own keys */
const REP_SEED = Buffer.alloc(32, 0x5a).toString('hex');
const TRUSTED_SEED = Buffer.alloc(32, 0x77).toString('hex');

function stapleBlocks(result) {
	return result.voteStaple.blocks.map(function(block) {
		return {
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase(),
			hash: block.hash.toString()
		};
	});
}

async function main() {
	const repKey = Account.fromSeed(REP_SEED, 0, AccountKeyAlgorithm.ED25519);
	const trustedKey = Account.fromSeed(TRUSTED_SEED, 0, AccountKeyAlgorithm.ED25519);

	const node = await createTestNode(repKey, {
		initialTrustedAccount: trustedKey
	});

	const ip = node.config.nodeOptions.listenIP;
	const port = node.config.nodeOptions.listenPort;

	const trustedClient = UserClient.fromSimpleSingleRep(
		`${ip}:${port}`,
		false,
		repKey,
		node.config.network,
		node.config.networkAlias,
		trustedKey
	);

	const handlers = {
		init_supply: async function(request) {
			const result = await trustedClient.initializeNetwork({
				addSupplyAmount: BigInt(request.amount)
			});
			return { event: 'initialized', blocks: stapleBlocks(result) };
		},

		send: async function(request) {
			const to = Account.fromPublicKeyString(request.to);
			const result = await trustedClient.send(to, BigInt(request.amount), node.baseToken, request.external);
			return { event: 'sent', blocks: stapleBlocks(result) };
		},

		set_info: async function(request) {
			const result = await trustedClient.setInfo({
				name: request.name,
				description: request.description,
				metadata: request.metadata
			});
			return { event: 'info_set', blocks: stapleBlocks(result) };
		},

		manage_cert_add: async function() {
			const certificate = await new CertificateBuilder({
				issuer: trustedKey,
				validFrom: new Date(Date.now() - (60 * 60 * 1000)),
				validTo: new Date(Date.now() + (365 * 24 * 60 * 60 * 1000))
			}).build({
				serial: 7,
				subjectPublicKey: trustedKey
			});

			const result = await trustedClient.modifyCertificate(AdjustMethod.ADD, certificate, null);
			return { event: 'certificate_added', blocks: stapleBlocks(result) };
		},

		head: async function(request) {
			const account = Account.fromPublicKeyString(request.account);
			const head = await trustedClient.client.getHeadBlock(account);
			const balance = await trustedClient.client.getBalance(account, node.baseToken);

			let headHash = null;
			if (head !== null) {
				headHash = head.hash.toString();
			}

			return { event: 'head', head: headHash, balance: balance.toString() };
		},

		transmit: async function(request) {
			const buffer = Buffer.from(request.bytes, 'hex');
			const arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
			const block = new Block(arrayBuffer);

			const result = await trustedClient.client.transmit([block]);
			return { event: 'transmitted', blocks: stapleBlocks(result), hash: block.hash.toString() };
		},

		shutdown: async function() {
			setImmediate(async function() {
				try {
					await trustedClient.client.destroy();
					await trustedClient.destroy();
					await node.stop();
				} finally {
					process.exit(0);
				}
			});
			return { event: 'shutdown' };
		}
	};

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
			let request;
			try {
				request = JSON.parse(line);
				const handler = handlers[request.cmd];
				if (handler === undefined) {
					throw(new Error(`Unknown command: ${request.cmd}`));
				}

				const response = await handler(request);
				console.log(JSON.stringify(response));
			} catch (error) {
				console.error(error);
				console.log(JSON.stringify({ error: String(error && error.message ? error.message : error) }));
			}
		});
	});
}

main().catch(function(error) {
	console.error(error);
	process.exit(1);
});
