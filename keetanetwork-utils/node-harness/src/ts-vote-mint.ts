/*
 * Mints a vote using the reference TypeScript implementation.
 *
 * Reads a JSON spec on stdin:
 *
 * ```
 * {
 *   issuerSeed: string,         // 32-byte hex-encoded seed
 *   issuerKeyType: 'ed25519' | 'ecdsa-secp256k1' | 'ecdsa-secp256r1',
 *   issuerIndex?: number,       // default 0
 *   serial: string,             // BigInt-as-string
 *   blocks: string[],           // block hashes (hex)
 *   validityFromMs: number,     // unix milliseconds
 *   validityToMs: number,       // unix milliseconds
 *   fee?: { amount: string, payTo?: string, token?: string }
 *       | { amount: string, payTo?: string, token?: string }[],
 *   quote?: boolean             // default false
 * }
 * ```
 *
 * Writes a JSON line to stdout: { bytes, hash, issuer } where bytes is
 * hex-encoded and issuer is the canonical public key string the minter
 * derived from the supplied seed + index + algorithm.
 *
 * Usage: node dist/ts_vote_mint.js <path-to-node-dist>
 */

import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as BlockIndexModule from '@keetanetwork/keetanet-node/dist/lib/block/index';
import type * as VoteModule from '@keetanetwork/keetanet-node/dist/lib/vote';

import { loadModule, resolveDist } from './dist';

const USAGE = 'usage: ts-vote-mint.js <path-to-node-dist>';

const dist = resolveDist(process.argv[2], USAGE);

const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { BlockHash } = loadModule<typeof BlockIndexModule>(dist, 'lib/block/index.js');
const { Vote, VoteQuote } = loadModule<typeof VoteModule>(dist, 'lib/vote.js');

interface FeeSpec {
	amount: string;
	payTo?: string;
	token?: string;
}

interface MintRequest {
	issuerSeed: string;
	issuerKeyType: 'ed25519' | 'ecdsa-secp256k1' | 'ecdsa-secp256r1';
	issuerIndex?: number;
	serial: string;
	blocks: string[];
	validityFromMs: number;
	validityToMs: number;
	fee?: FeeSpec | FeeSpec[];
	quote?: boolean;
}

function algorithmFor(keyType: MintRequest['issuerKeyType']): AccountModule.AccountKeyAlgorithm {
	switch (keyType) {
		case 'ed25519':
			return(AccountKeyAlgorithm.ED25519);
		case 'ecdsa-secp256k1':
			return(AccountKeyAlgorithm.ECDSA_SECP256K1);
		case 'ecdsa-secp256r1':
			return(AccountKeyAlgorithm.ECDSA_SECP256R1);
		default: {
			throw(new Error(`unsupported issuer key type: ${keyType}`));
		}
	}
}

function feeAmountAndToken(spec: FeeSpec): VoteModule.FeeAmountAndToken {
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const out = { amount: BigInt(spec.amount) } as VoteModule.FeeAmountAndToken;
	if (spec.payTo !== undefined) {
		const account = Account.toAccount(spec.payTo);
		if (account === null) {
			throw(new Error(`fee payTo ${spec.payTo} could not be resolved to an account`));
		}

		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		(out as { payTo: typeof account }).payTo = account;
	}
	if (spec.token !== undefined) {
		const token = Account.toAccount(spec.token);
		if (token === null) {
			throw(new Error(`fee token ${spec.token} could not be resolved to an account`));
		}

		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		(out as { token: typeof token }).token = token;
	}
	return(out);
}

function readStdin(): Promise<string> {
	return(new Promise(function(resolve, reject) {
		let buffer = '';
		process.stdin.setEncoding('utf8');
		process.stdin.on('data', function(chunk: string) {
			buffer += chunk;
		});
		process.stdin.on('end', function() {
			resolve(buffer);
		});
		process.stdin.on('error', reject);
	}));
}

async function main(): Promise<void> {
	const raw = await readStdin();
	if (raw.trim() === '') {
		throw(new Error('no input on stdin'));
	}

	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const request = JSON.parse(raw) as MintRequest;

	const issuer = Account.fromSeed(request.issuerSeed, request.issuerIndex ?? 0, algorithmFor(request.issuerKeyType));
	const blockHashes = request.blocks.map(function(hex) {
		return(new BlockHash(hex));
	});

	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const issuerAccount = issuer as ConstructorParameters<typeof Vote.Builder>[0];
	const builder = (function() {
		if (request.quote === true) {
			return(new VoteQuote.Builder(issuerAccount));
		}

		return(new Vote.Builder(issuerAccount));
	})();
	builder.addBlocks(blockHashes);

	if (request.fee !== undefined) {
		if (Array.isArray(request.fee)) {
			builder.addFee(request.fee.map(feeAmountAndToken));
		} else {
			builder.addFee(feeAmountAndToken(request.fee));
		}
	}

	const validFrom = new Date(request.validityFromMs);
	const validTo = new Date(request.validityToMs);
	const vote = await builder.seal(BigInt(request.serial), validTo, validFrom);

	const bytes = Buffer.from(vote.toBytes()).toString('hex').toUpperCase();
	const hash = vote.hash.toString();
	const issuerString = issuer.publicKeyString.get();
	console.log(JSON.stringify({ bytes, hash, issuer: issuerString }));
}

main().catch(function(error: unknown) {
	console.error(error);
	process.exit(1);
});
