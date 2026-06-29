/*
 * Unified reference-implementation harness.
 *
 * Speaks the shared harness JSON-lines protocol: one JSON request object
 * per stdin line carrying a `cmd` discriminator, one JSON response line
 * per request.
 *
 * Commands:
 *   { cmd: "account_generate", seedHex, index, passphrase, messageHex,
 *     plaintextHex, algorithms }                  -> { accounts }
 *   { cmd: "account_verify", seedHex, index, messageHex, plaintextHex,
 *     results }                                    -> { ok: true }
 *   { cmd: "cert_mint", subject }                  -> { der }
 *   { cmd: "vote_mint", issuerSeed, issuerKeyType, issuerIndex?, serial,
 *     blocks, validityFromMs, validityToMs, fee?, quote? }
 *                                                  -> { bytes, hash, issuer }
 *   { cmd: "vote_verify", bytes }                  -> { hash, bytes, serial,
 *     issuer, blocks, validityFrom, validityTo, fee?, quote? }
 *   { cmd: "block_verify", blocks }                -> { blocks: [{hash,bytes}] }
 *
 * Usage: node dist/ts-ref.js <path-to-node-dist>
 */

import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';
import type * as CertificateModule from '@keetanetwork/keetanet-node/dist/lib/utils/certificate';
import type * as VoteModule from '@keetanetwork/keetanet-node/dist/lib/vote';

import type { DispatchRequest } from './dist';
import { hexToArrayBuffer, loadModule, resolveDist, runJsonLines, toHex } from './dist';

const dist = resolveDist(process.argv[2], 'usage: ts-ref.js <path-to-node-dist>');

const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { Block, BlockHash } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');
const { Vote, VoteQuote } = loadModule<typeof VoteModule>(dist, 'lib/vote.js');
const { CertificateBuilder } = loadModule<typeof CertificateModule>(dist, 'lib/utils/certificate.js');

/* Deterministic certificate issuer, matching the historical mint helper. */
const CERT_ISSUER_SEED = Buffer.alloc(32, 0x77).toString('hex');

/*
 * Resolve an algorithm token to the SDK enum. The underscore spelling is
 * the canonical wire vocabulary across the project (WIT world, Java
 * `Algorithm`, bindings defaults).
 */
function algorithmFor(name: string): AccountModule.AccountKeyAlgorithm {
	switch (name) {
		case 'ed25519':
			return(AccountKeyAlgorithm.ED25519);
		case 'ecdsa_secp256k1':
			return(AccountKeyAlgorithm.ECDSA_SECP256K1);
		case 'ecdsa_secp256r1':
			return(AccountKeyAlgorithm.ECDSA_SECP256R1);
		default:
			throw(new Error(`unsupported algorithm: ${String(name)}`));
	}
}

function assert(condition: boolean, message: string): void {
	if (!condition) {
		throw(new Error(message));
	}
}

// -- accounts ----------------------------------------------------------------

interface AccountGenerateRequest extends DispatchRequest {
	seedHex: string;
	index: number;
	passphrase: string;
	messageHex: string;
	plaintextHex: string;
	algorithms: string[];
}

interface ImplResult {
	signatureHex: string;
	ciphertextHex: string;
	ciphertextPubHex: string;
}

interface AccountVerifyRequest extends DispatchRequest {
	seedHex: string;
	index: number;
	messageHex: string;
	plaintextHex: string;
	results: { [algorithm: string]: ImplResult };
}

async function accountGenerate(request: AccountGenerateRequest): Promise<unknown> {
	const message = hexToArrayBuffer(request.messageHex);
	const plaintext = hexToArrayBuffer(request.plaintextHex);
	const passphraseSeed = await Account.seedFromPassphrase(request.passphrase);
	const accounts: { [algorithm: string]: unknown } = {};
	for (const name of request.algorithms) {
		const algorithm = algorithmFor(name);
		const account = Account.fromSeed(request.seedHex, request.index, algorithm);
		const privateKey = Account.KeyPairs[algorithm].derivePrivateKeyFromSeed(request.seedHex, request.index);
		const signature = await account.sign(message);
		const ciphertext = await account.encrypt(plaintext);
		const passphraseAccount = Account.fromSeed(passphraseSeed, request.index, algorithm);

		accounts[name] = {
			address: account.publicKeyString.toString(),
			publicKeyHex: toHex(account.publicKeyAndType),
			rawPublicKeyHex: account.publicKey.toString('hex'),
			privateKeyHex: privateKey.toString('hex'),
			signatureHex: signature.toString('hex'),
			ciphertextHex: toHex(ciphertext),
			passphraseAddress: passphraseAccount.publicKeyString.toString(),
			passphrasePublicKeyHex: toHex(passphraseAccount.publicKeyAndType)
		};
	}

	return({ accounts });
}

async function accountVerify(request: AccountVerifyRequest): Promise<unknown> {
	const message = hexToArrayBuffer(request.messageHex);
	for (const name of Object.keys(request.results)) {
		const result = request.results[name];
		const algorithm = algorithmFor(name);
		const account = Account.fromSeed(request.seedHex, request.index, algorithm);

		assert(
			account.verify(message, hexToArrayBuffer(result.signatureHex)),
			`reference SDK rejected the ${name} signature`
		);
		assert(
			toHex(await account.decrypt(hexToArrayBuffer(result.ciphertextHex))) === request.plaintextHex,
			`reference SDK could not decrypt the ${name} keypair ciphertext`
		);
		assert(
			toHex(await account.decrypt(hexToArrayBuffer(result.ciphertextPubHex))) === request.plaintextHex,
			`reference SDK could not decrypt the ${name} read-only ciphertext`
		);
	}

	return({ ok: true });
}

// -- certificates ------------------------------------------------------------

interface CertMintRequest extends DispatchRequest {
	subject: string;
}

async function certMint(request: CertMintRequest): Promise<unknown> {
	const issuer = Account.fromSeed(CERT_ISSUER_SEED, 0, AccountKeyAlgorithm.ED25519);
	const subject = Account.fromPublicKeyString(request.subject).assertKeyType(AccountKeyAlgorithm.ED25519);

	const certificate = await new CertificateBuilder({
		issuer,
		validFrom: new Date('2025-01-01T00:00:00.000Z'),
		validTo: new Date('2035-01-01T00:00:00.000Z')
	}).build({
		serial: 7,
		subjectPublicKey: subject
	});

	return({ der: Buffer.from(certificate.toDER()).toString('hex').toUpperCase() });
}

// -- votes -------------------------------------------------------------------

interface FeeSpec {
	amount: string;
	payTo?: string;
	token?: string;
}

interface VoteMintRequest extends DispatchRequest {
	issuerSeed: string;
	issuerKeyType: string;
	issuerIndex?: number;
	serial: string;
	blocks: string[];
	validityFromMs: number;
	validityToMs: number;
	fee?: FeeSpec | FeeSpec[];
	quote?: boolean;
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

async function voteMint(request: VoteMintRequest): Promise<unknown> {
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

	return({
		bytes: Buffer.from(vote.toBytes()).toString('hex').toUpperCase(),
		hash: vote.hash.toString(),
		issuer: issuer.publicKeyString.get()
	});
}

interface VoteVerifyRequest extends DispatchRequest {
	bytes: string;
}

interface KeetaPublicKeyHolder {
	publicKeyString: { get(): string };
}

interface SerializableFee {
	amount: bigint;
	payTo?: KeetaPublicKeyHolder;
	token?: KeetaPublicKeyHolder;
}

function serializeSingleFee(entry: SerializableFee): unknown {
	const single: { [key: string]: unknown } = {
		amount: entry.amount.toString()
	};
	if (entry.payTo !== undefined) {
		single['payTo'] = entry.payTo.publicKeyString.get();
	}
	if (entry.token !== undefined) {
		single['token'] = entry.token.publicKeyString.get();
	}

	return(single);
}

function serializeFee(fee: VoteModule.Vote['fee']): unknown {
	if (Array.isArray(fee)) {
		return(fee.map(function(entry) {
			return(serializeSingleFee(entry));
		}));
	}
	if (fee === undefined) {
		return(undefined);
	}

	return(serializeSingleFee(fee));
}

/**
 * `Vote` rejects quote=true certificates and `VoteQuote` rejects quote=false ones.
 */
function parseVote(arrayBuffer: ArrayBuffer): VoteModule.Vote | VoteModule.VoteQuote {
	try {
		return(new Vote(arrayBuffer));
	} catch (error) {
		let code: string | undefined;
		if (error !== null && typeof error === 'object' && 'code' in error && typeof error.code === 'string') {
			code = error.code;
		}
		if (code !== 'VOTE_MALFORMED_FEES_QUOTE_INVALID') {
			throw(error);
		}

		return(new VoteQuote(arrayBuffer));
	}
}

function voteVerify(request: VoteVerifyRequest): unknown {
	const vote = parseVote(hexToArrayBuffer(request.bytes));
	const blocks: string[] = vote.blocks.map(function(blockHash) {
		return(blockHash.toString());
	});

	const result: { [key: string]: unknown } = {
		hash: vote.hash.toString(),
		bytes: Buffer.from(vote.toBytes()).toString('hex').toUpperCase(),
		serial: vote.serial.toString(),
		issuer: vote.issuer.publicKeyString.get(),
		blocks: blocks,
		validityFrom: vote.validityFrom.toISOString(),
		validityTo: vote.validityTo.toISOString()
	};

	if (vote.fee !== undefined) {
		result['fee'] = serializeFee(vote.fee);
	}
	if (vote.quote !== undefined) {
		result['quote'] = vote.quote;
	}

	return(result);
}

// -- blocks ------------------------------------------------------------------

interface BlockVerifyRequest extends DispatchRequest {
	blocks: string[];
}

function blockVerify(request: BlockVerifyRequest): unknown {
	const blocks = request.blocks.map(function(hex) {
		const block = new Block(hexToArrayBuffer(hex));
		return({
			hash: block.hash.toString(),
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase()
		});
	});

	return({ blocks });
}

// -- dispatch ----------------------------------------------------------------

function handle(request: DispatchRequest): Promise<unknown> {
	switch (request.cmd) {
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'account_generate': return(accountGenerate(request as AccountGenerateRequest));
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'account_verify': return(accountVerify(request as AccountVerifyRequest));
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'cert_mint': return(certMint(request as CertMintRequest));
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'vote_mint': return(voteMint(request as VoteMintRequest));
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'vote_verify': return(Promise.resolve(voteVerify(request as VoteVerifyRequest)));
		// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
		case 'block_verify': return(Promise.resolve(blockVerify(request as BlockVerifyRequest)));
		default: throw(new Error(`unknown command: ${JSON.stringify(request)}`));
	}
}

runJsonLines(handle);
