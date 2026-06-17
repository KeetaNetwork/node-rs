/*
 * End-to-end harness: runs a live local reference node (in-memory
 * ledger) and exposes it over a JSON-lines protocol on stdin/stdout.
 *
 * Usage: node dist/e2e_node.js <path-to-node-dist> [--fee=<amount>] [--reps=<count>]
 *
 * With `--reps=N` (N > 1) the harness boots N peered representative nodes
 * (P2P enabled) sharing one trusted/genesis account, and the ready payload
 * carries a `reps` array of `{ api, account }`. The first rep stays
 * backwards-compatible with the single-node fields.
 *
 * Commands:
 *   { cmd: "init_supply", amount }            mint initial supply to the trusted account
 *   { cmd: "send", to, amount, external? }    send base token from the trusted account
 *   { cmd: "build_send", to, amount }         build (but do not publish) a send block
 *   { cmd: "set_info", name, description, metadata }
 *   { cmd: "manage_cert_add" }                add a freshly minted certificate to the trusted account
 *   { cmd: "head", account }                  head hash + base token balance for an account
 *   { cmd: "head_all", account }              head hash on every node (P2P convergence probe)
 *   { cmd: "stop_rep", index }                stop one representative node (rep-failure probe)
 *   { cmd: "side_vote", node, block, prior? } stage a side-ledger vote on one node (recover probe)
 *   { cmd: "ledger_add", node, votes, block } promote a staple onto one node's main ledger (sync probe)
 *   { cmd: "transmit", bytes }                publish externally built block bytes to the node
 *   { cmd: "transmit_staple", bytes }         publish externally built staple bytes to the node
 *   { cmd: "build_staple", bytes }            assemble a fresh staple around a Rust-built block
 *   { cmd: "verify_staple", bytes }           parse staple bytes and report hash + element counts
 *   { cmd: "shutdown" }                       stop the node and exit
 */

import * as readline from 'node:readline';

import type * as ClientModule from '@keetanetwork/keetanet-node/dist/client/index';
import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';
import type * as CertificateModule from '@keetanetwork/keetanet-node/dist/lib/utils/certificate';
import type * as HelperTestingModule from '@keetanetwork/keetanet-node/dist/lib/utils/helper_testing';
import type * as VoteModule from '@keetanetwork/keetanet-node/dist/lib/vote';
import type { Block as BlockInstance } from '@keetanetwork/keetanet-node/dist/lib/block/index';

import { loadModule, resolveDist } from './dist';

const dist = resolveDist(process.argv[2], 'usage: e2e_node.js <path-to-node-dist>');

const { UserClient } = loadModule<typeof ClientModule>(dist, 'client/index.js');
const { createTestNode, testingNetworkId } = loadModule<typeof HelperTestingModule>(dist, 'lib/utils/helper_testing.js');
const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { Block, AdjustMethod } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');
const { CertificateBuilder } = loadModule<typeof CertificateModule>(dist, 'lib/utils/certificate.js');
const { Vote, VoteStaple } = loadModule<typeof VoteModule>(dist, 'lib/vote.js');

/* Deterministic harness accounts; the "rust" side derives its own keys */
const REP_SEED = Buffer.alloc(32, 0x5a).toString('hex');
const TRUSTED_SEED = Buffer.alloc(32, 0x77).toString('hex');

/* Optional `--fee=<amount>` argv boots a fee-enforcing node so the Rust
 * client's fee block origination path can be exercised. */
function parseFeeAmount(args: string[]): bigint | undefined {
	for (const arg of args) {
		const match = /^--fee=(\d+)$/.exec(arg);
		if (match !== null) {
			return(BigInt(match[1]));
		}
	}

	return(undefined);
}

const feeAmount = parseFeeAmount(process.argv.slice(3));

/* Optional `--reps=<count>` argv boots a peered multi-representative cluster
 * so the Rust client's fan-out, quorum, and convergence paths can be
 * exercised live. Defaults to a single node. */
function parseRepCount(args: string[]): number {
	for (const arg of args) {
		const match = /^--reps=(\d+)$/.exec(arg);
		if (match !== null) {
			return(Math.max(1, Number(match[1])));
		}
	}

	return(1);
}

const repCount = parseRepCount(process.argv.slice(3));

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

interface BuildSendRequest {
	cmd: 'build_send';
	to: string;
	amount: string;
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

interface HeadAllRequest {
	cmd: 'head_all';
	account: string;
}

interface StopRepRequest {
	cmd: 'stop_rep';
	index: number;
}

interface SideVoteRequest {
	cmd: 'side_vote';
	node: number;
	block: string;
	prior?: string[];
}

interface LedgerAddRequest {
	cmd: 'ledger_add';
	node: number;
	votes: string[];
	block: string;
}

interface TransmitRequest {
	cmd: 'transmit';
	bytes: string;
}

interface TransmitStapleRequest {
	cmd: 'transmit_staple';
	bytes: string;
}

interface BuildStapleRequest {
	cmd: 'build_staple';
	bytes: string;
}

interface VerifyStapleRequest {
	cmd: 'verify_staple';
	bytes: string;
}

interface ShutdownRequest {
	cmd: 'shutdown';
}

type HarnessRequest =
	InitSupplyRequest |
	SendRequest |
	BuildSendRequest |
	SetInfoRequest |
	ManageCertAddRequest |
	HeadRequest |
	HeadAllRequest |
	StopRepRequest |
	SideVoteRequest |
	LedgerAddRequest |
	TransmitRequest |
	TransmitStapleRequest |
	BuildStapleRequest |
	VerifyStapleRequest |
	ShutdownRequest;

interface DirectResult {
	voteStaple: {
		blocks: BlockInstance[];
		toBytes: () => ArrayBuffer;
	};
}

interface PublishAidResult {
	blocks: BlockModule.Block[];
}

function stapleBlocks(result: DirectResult | PublishAidResult): { bytes: string; hash: string }[] {
	let blocks: BlockModule.Block[];
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

function stapleBytes(result: DirectResult | PublishAidResult): string | null {
	if ('voteStaple' in result) {
		const bytes = result.voteStaple.toBytes();
		return(Buffer.from(new Uint8Array(bytes)).toString('hex').toUpperCase());
	}

	return(null);
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
	const buffer = Buffer.from(hex, 'hex');
	return(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
}

type TestNode = Awaited<ReturnType<typeof createTestNode>>;

function nodeHostPort(node: TestNode): string {
	const options = node.config.nodeOptions;
	if (options === undefined) {
		throw(new Error('test node did not report listen options'));
	}

	return(`${options.listenIP}:${options.listenPort}`);
}

async function main(): Promise<void> {
	const trustedKey = Account.fromSeed(TRUSTED_SEED, 0, AccountKeyAlgorithm.ED25519);
	const repKeys: AccountModule.Account[] = [];
	for (let index = 0; index < repCount; index++) {
		repKeys.push(Account.fromSeed(REP_SEED, index, AccountKeyAlgorithm.ED25519));
	}

	const repKey = repKeys[0];

	let ledgerOptions: NonNullable<Parameters<typeof createTestNode>[1]>['ledger'];
	if (feeAmount !== undefined) {
		/*
		 * Charge a flat base-token fee paid to the representative on every transaction.
		 */
		const { baseToken } = Account.generateBaseAddresses(testingNetworkId);
		ledgerOptions = {
			computeFeeFromBlocks: function() {
				return({ amount: feeAmount, token: baseToken, payTo: repKey });
			}
		};
	}

	/*
	 * A cluster (repCount > 1) peers each node with the ones booted before it
	 * and enables P2P so a staple published to one rep replicates to the
	 * rest; a lone node keeps P2P off to match the original harness.
	 */
	const enableP2P = repCount > 1;
	const nodes: TestNode[] = [];
	for (let index = 0; index < repCount; index++) {
		const node = await createTestNode(repKeys[index], {
			initialTrustedAccount: trustedKey,
			ledger: ledgerOptions,
			peerNodes: nodes.slice(),
			enableP2P: enableP2P
		});
		nodes.push(node);
	}

	const node = nodes[0];

	/* Reps stopped via `stop_rep` are skipped by `head_all` so a downed node
	 * does not stall convergence probes over the survivors. */
	const stopped = new Set<number>();

	const clients = nodes.map(function(member, index) {
		return(UserClient.fromSimpleSingleRep(
			nodeHostPort(member),
			false,
			repKeys[index],
			member.config.network,
			member.config.networkAlias,
			trustedKey
		));
	});
	const trustedClient = clients[0];

	async function handleInitSupply(request: InitSupplyRequest): Promise<{ [key: string]: unknown }> {
		const result = await trustedClient.initializeNetwork({
			addSupplyAmount: BigInt(request.amount)
		});
		return({ event: 'initialized', blocks: stapleBlocks(result) });
	}

	async function handleSend(request: SendRequest): Promise<{ [key: string]: unknown }> {
		const to = Account.fromPublicKeyString(request.to);
		const result = await trustedClient.send(to, BigInt(request.amount), node.baseToken, request.external);
		return({ event: 'sent', blocks: stapleBlocks(result) });
	}

	async function handleBuildSend(request: BuildSendRequest): Promise<{ [key: string]: unknown }> {
		const to = Account.fromPublicKeyString(request.to);

		/*
		 * Build and sign the send block without publishing it so the
		 * Rust client owns the transmit (vote + staple + publish).
		 */
		const builder = trustedClient.initBuilder();
		builder.send(to, BigInt(request.amount), node.baseToken);

		const result = await builder.computeBlocks();
		return({ event: 'send_built', blocks: stapleBlocks(result) });
	}

	async function handleSetInfo(request: SetInfoRequest): Promise<{ [key: string]: unknown }> {
		const result = await trustedClient.setInfo({
			name: request.name,
			description: request.description,
			metadata: request.metadata
		});
		return({ event: 'info_set', blocks: stapleBlocks(result) });
	}

	async function handleManageCertAdd(): Promise<{ [key: string]: unknown }> {
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

	async function handleHead(request: HeadRequest): Promise<{ [key: string]: unknown }> {
		const account = Account.fromPublicKeyString(request.account);
		const head = await trustedClient.client.getHeadBlock(account);
		const balance = await trustedClient.client.getBalance(account, node.baseToken);

		let headHash: string | null = null;
		if (head !== null) {
			headHash = head.hash.toString();
		}

		return({ event: 'head', head: headHash, balance: balance.toString() });
	}

	async function handleHeadAll(request: HeadAllRequest): Promise<{ [key: string]: unknown }> {
		const account = Account.fromPublicKeyString(request.account);
		const heads: (string | null)[] = [];
		for (let index = 0; index < clients.length; index++) {
			if (stopped.has(index)) {
				continue;
			}

			const head = await clients[index].client.getHeadBlock(account);
			if (head === null) {
				heads.push(null);
			} else {
				heads.push(head.hash.toString());
			}
		}

		return({ event: 'head_all', heads: heads });
	}

	function requireLiveNode(index: number, label: string): void {
		if (!Number.isInteger(index) || index < 0 || index >= nodes.length || stopped.has(index)) {
			throw(new Error(`${label} node out of range: ${String(index)}`));
		}
	}

	async function handleStopRep(request: StopRepRequest): Promise<{ [key: string]: unknown }> {
		const index = request.index;
		if (!Number.isInteger(index) || index < 0 || index >= nodes.length) {
			throw(new Error(`stop_rep index out of range: ${String(index)}`));
		}

		stopped.add(index);
		try {
			await clients[index].client.destroy();
			await clients[index].destroy();
		} catch {
			/*
			 * The client may already be torn down; stopping the node is what matters.
			 */
		}

		await nodes[index].stop();

		return({ event: 'rep_stopped', index: index });
	}

	async function handleSideVote(request: SideVoteRequest): Promise<{ [key: string]: unknown }> {
		const index = request.node;
		requireLiveNode(index, 'side_vote');

		const block = new Block(hexToArrayBuffer(request.block));
		const prior = request.prior ?? [];
		const priorVotes = prior.map(function(hex) {
			return(new Vote(hexToArrayBuffer(hex)));
		});

		/* A vote with no priors is temporary (side ledger); a vote
		 * carrying the temporary votes escalates to permanent. */
		let vote;
		if (priorVotes.length > 0) {
			vote = await nodes[index].ledger.vote([block], priorVotes);
		} else {
			vote = await nodes[index].ledger.vote([block]);
		}

		return({
			event: 'side_voted',
			vote: Buffer.from(new Uint8Array(vote.toBytes())).toString('hex').toUpperCase()
		});
	}

	async function handleLedgerAdd(request: LedgerAddRequest): Promise<{ [key: string]: unknown }> {
		const index = request.node;
		requireLiveNode(index, 'ledger_add');

		const block = new Block(hexToArrayBuffer(request.block));
		const votes = request.votes.map(function(hex) {
			return(new Vote(hexToArrayBuffer(hex)));
		});

		const staple = VoteStaple.fromVotesAndBlocks(votes, [block]);
		const result = await nodes[index].ledger.add(staple);

		return({ event: 'ledger_added', blocksHash: result[0].blocksHash.toString() });
	}

	async function handleTransmit(request: TransmitRequest): Promise<{ [key: string]: unknown }> {
		const block = new Block(hexToArrayBuffer(request.bytes));

		const result = await trustedClient.client.transmit([block]);
		return({
			event: 'transmitted',
			blocks: stapleBlocks(result),
			stapleBytes: stapleBytes(result),
			hash: block.hash.toString()
		});
	}

	async function handleTransmitStaple(request: TransmitStapleRequest): Promise<{ [key: string]: unknown }> {
		const staple = new VoteStaple(hexToArrayBuffer(request.bytes));

		const result = await trustedClient.client.transmitStaple(staple);
		const voteHashes = staple.votes.map(function(vote) {
			return(vote.hash.toString());
		});
		const blockHashes = staple.blocks.map(function(block) {
			return(block.hash.toString());
		});
		return({
			event: 'staple_transmitted',
			stapleHash: staple.hash.toString(),
			blockHashes: blockHashes,
			voteHashes: voteHashes,
			blocks: stapleBlocks(result),
			publish: result.publish
		});
	}

	async function handleVerifyStaple(request: VerifyStapleRequest): Promise<{ [key: string]: unknown }> {
		/* Pure parse + hash; intentionally never calls transmitStaple
		 * to avoid the "Block Already Exists / Internal error" path
		 * when callers reuse blocks across scenarios. */
		const staple = new VoteStaple(hexToArrayBuffer(request.bytes));
		const voteHashes = staple.votes.map(function(vote) {
			return(vote.hash.toString());
		});
		const blockHashes = staple.blocks.map(function(block) {
			return(block.hash.toString());
		});
		return({
			event: 'staple_verified',
			stapleHash: staple.hash.toString(),
			blockHashes: blockHashes,
			voteHashes: voteHashes
		});
	}

	async function handleBuildStaple(request: BuildStapleRequest): Promise<{ [key: string]: unknown }> {
		const block = new Block(hexToArrayBuffer(request.bytes));

		const validFrom = new Date(Date.now() - (60 * 1000));
		const validTo = new Date(Date.now() + (60 * 60 * 1000));

		/* Two votes from the local rep and trusted accounts ensure the
		 * resulting staple has the same shape transmit() would produce. */
		const repBuilder = new Vote.Builder(repKey);
		repBuilder.addBlocks([block.hash]);
		const repVote = await repBuilder.seal(1n, validTo, validFrom);

		const trustedBuilder = new Vote.Builder(trustedKey);
		trustedBuilder.addBlocks([block.hash]);
		const trustedVote = await trustedBuilder.seal(1n, validTo, validFrom);

		const staple = VoteStaple.fromVotesAndBlocks([repVote, trustedVote], [block]);
		const stapleBuffer = Buffer.from(staple.toBytes());
		return({
			event: 'staple_built',
			bytes: stapleBuffer.toString('hex').toUpperCase(),
			stapleHash: staple.hash.toString()
		});
	}

	function handleShutdown(): { [key: string]: unknown } {
		setImmediate(async function() {
			try {
				for (let index = 0; index < clients.length; index++) {
					if (stopped.has(index)) {
						continue;
					}

					try {
						await clients[index].client.destroy();
						await clients[index].destroy();
						await nodes[index].stop();
					} catch {
						/*
						 * Best-effort teardown; the process exit below reaps everything.
						 */
					}
				}
			} finally {
				process.exit(0);
			}
		});
		return({ event: 'shutdown' });
	}

	function handleRequest(request: HarnessRequest): Promise<{ [key: string]: unknown }> {
		switch (request.cmd) {
			case 'init_supply': return(handleInitSupply(request));
			case 'send': return(handleSend(request));
			case 'build_send': return(handleBuildSend(request));
			case 'set_info': return(handleSetInfo(request));
			case 'manage_cert_add': return(handleManageCertAdd());
			case 'head': return(handleHead(request));
			case 'head_all': return(handleHeadAll(request));
			case 'stop_rep': return(handleStopRep(request));
			case 'side_vote': return(handleSideVote(request));
			case 'ledger_add': return(handleLedgerAdd(request));
			case 'transmit': return(handleTransmit(request));
			case 'transmit_staple': return(handleTransmitStaple(request));
			case 'verify_staple': return(handleVerifyStaple(request));
			case 'build_staple': return(handleBuildStaple(request));
			case 'shutdown': return(Promise.resolve(handleShutdown()));
			default: throw(new Error(`Unknown command: ${JSON.stringify(request)}`));
		}
	}

	const reps = nodes.map(function(member, index) {
		return({
			api: `http://${nodeHostPort(member)}/api`,
			account: repKeys[index].publicKeyString.get()
		});
	});

	console.log(JSON.stringify({
		event: 'ready',
		api: `http://${nodeHostPort(node)}/api`,
		network: node.config.network.toString(),
		networkAlias: node.config.networkAlias,
		baseToken: node.baseToken.publicKeyString.get(),
		trusted: trustedKey.publicKeyString.get(),
		representative: repKey.publicKeyString.get(),
		reps: reps
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
