/*
 * Generates the checked-in block transport fixtures from the reference
 * TypeScript implementation.
 *
 * Usage: node dist/generate_fixtures.js <path-to-node-dist> <output-json>
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';
import type * as OperationsModule from '@keetanetwork/keetanet-node/dist/lib/block/operations';
import type * as PermissionsModule from '@keetanetwork/keetanet-node/dist/lib/permissions';
import type * as CertificateModule from '@keetanetwork/keetanet-node/dist/lib/utils/certificate';

import { loadModule, resolveDist, resolveOutputPath } from './dist';

const USAGE = 'usage: generate_fixtures.js <path-to-node-dist> <output-json>';

const dist = resolveDist(process.argv[2], USAGE);
const outFile = resolveOutputPath(process.argv[3], USAGE);

const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { UnsignedBlock, BlockHash, BlockPurpose, AdjustMethod } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');
const { Permissions } = loadModule<typeof PermissionsModule>(dist, 'lib/permissions.js');
const { CertificateHash, CertificateBuilder } = loadModule<typeof CertificateModule>(dist, 'lib/utils/certificate.js');
const Operations = loadModule<typeof OperationsModule>(dist, 'lib/block/operations.js');

const SEED = Buffer.alloc(32, 0x5a).toString('hex');

function account<Z extends AccountModule.AccountKeyAlgorithm>(index: number, algorithm: Z): AccountModule.Account<Z>;
function account(index: number): AccountModule.Account<AccountModule.AccountKeyAlgorithm.ED25519>;
function account(index: number, algorithm?: AccountModule.AccountKeyAlgorithm): AccountModule.Account<AccountModule.AccountKeyAlgorithm> {
	return(Account.fromSeed(SEED, index, algorithm ?? AccountKeyAlgorithm.ED25519));
}

const DATE_MS = new Date('2025-06-01T12:34:56.789Z');
const DATE_PLAIN = new Date('2025-06-01T12:34:56.000Z');
const OLD_DATE = new Date('2024-01-02T03:04:05.500Z');
const NETWORK = 0n;

interface BuiltBlock {
	block: BlockModule.Block;
	unsignedBytes: string;
}

async function buildBlock(input: BlockModule.BlockJSONIncomplete): Promise<BuiltBlock> {
	const blockInput: BlockModule.BlockJSONIncomplete = {
		network: NETWORK,
		date: DATE_MS,
		purpose: BlockPurpose.GENERIC,
		version: 2,
		...input
	};

	/*
	 * Each case provides the remaining required fields; the constructor
	 * type only accepts the fully assembled JSON shape.
	 */
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	const unsigned = new UnsignedBlock(blockInput as BlockModule.BlockJSON);

	const unsignedBytes = Buffer.from(unsigned.toBytes(false)).toString('hex').toUpperCase();
	const block = await unsigned.seal();
	return({ block, unsignedBytes });
}

async function main(): Promise<void> {
	const signerA = account(0);
	const signerB = account(1);
	const signerC = account(2, AccountKeyAlgorithm.ECDSA_SECP256K1);
	const signerD = account(3, AccountKeyAlgorithm.ECDSA_SECP256R1);
	const tokenOwner = account(4);

	const openingA = BlockHash.getAccountOpeningHash(signerA);
	const prevHash = new BlockHash(Buffer.alloc(32, 0x11).toString('hex'));

	const token = tokenOwner.generateIdentifier(
		AccountKeyAlgorithm.TOKEN,
		BlockHash.getAccountOpeningHash(tokenOwner),
		0
	);
	const storage = tokenOwner.generateIdentifier(
		AccountKeyAlgorithm.STORAGE,
		BlockHash.getAccountOpeningHash(tokenOwner),
		1
	);
	const multisigAddr = tokenOwner.generateIdentifier(
		AccountKeyAlgorithm.MULTISIG,
		BlockHash.getAccountOpeningHash(tokenOwner),
		2
	);
	const multisigNested = tokenOwner.generateIdentifier(
		AccountKeyAlgorithm.MULTISIG,
		BlockHash.getAccountOpeningHash(tokenOwner),
		3
	);

	const send: OperationsModule.BlockJSONOperationSEND = {
		type: Operations.OperationType.SEND,
		to: signerB,
		amount: 1000n,
		token
	};

	/* Identifiers and the certificate are derived up front so the case
	 * table below can be a single array literal. */
	const createdToken = signerA.generateIdentifier(AccountKeyAlgorithm.TOKEN, openingA, 0);
	const createdMultisig = signerA.generateIdentifier(AccountKeyAlgorithm.MULTISIG, prevHash, 0);
	const certificate = await new CertificateBuilder({
		issuer: signerA,
		validFrom: new Date('2025-01-01T00:00:00.000Z'),
		validTo: new Date('2035-01-01T00:00:00.000Z')
	}).build({
		serial: 1,
		subjectPublicKey: signerA
	});

	const cases: [string, BuiltBlock][] = [
		/* V1: signer == account (account encodes as NULL), subnet absent (NULL) */
		['v1-basic', await buildBlock({
			version: 1,
			purpose: undefined,
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [send]
		})],
		/* V1: subnet + idempotent + signer != account + explicit previous */
		['v1-full', await buildBlock({
			version: 1,
			purpose: undefined,
			account: signerB,
			signer: signerA,
			subnet: 0x1234n,
			idempotent: Buffer.from('0102030405060708090a0b0c', 'hex'),
			previous: prevHash,
			operations: [send],
			date: DATE_PLAIN
		})],
		/* V2: send with external, signer == account (NULL signer) */
		['v2-send-external', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{ ...send, external: 'payment ref 42' }]
		})],
		/* V2: send with empty external string */
		['v2-send-external-empty', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{ ...send, external: '' }]
		})],
		/* V2: negative amount allowed before the numeric cutoff */
		['v2-send-negative-olddate', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			date: OLD_DATE,
			operations: [{ ...send, amount: -5n }]
		})],
		/* V2: subnet + idempotent + distinct signer */
		['v2-full-header', await buildBlock({
			account: signerB,
			signer: signerA,
			subnet: 99n,
			idempotent: Buffer.from('00ff00ff', 'hex'),
			previous: prevHash,
			operations: [send]
		})],
		/* V2: FEE purpose (SEND only) */
		['v2-fee', await buildBlock({
			purpose: BlockPurpose.FEE,
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [send]
		})],
		/* V2: receive with forward + exact */
		['v2-receive-forward', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.RECEIVE,
				amount: 250n,
				token,
				from: signerB,
				exact: true,
				forward: signerB
			}]
		})],
		/* V2: receive without forward */
		['v2-receive-plain', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.RECEIVE,
				amount: 1n,
				token,
				from: signerC,
				exact: false
			}]
		})],
		/* V2: set rep */
		['v2-setrep', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{ type: Operations.OperationType.SET_REP, to: signerB }]
		})],
		/* V2: set info without default permissions */
		['v2-setinfo', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.SET_INFO,
				name: 'MY_ACCOUNT',
				description: 'A test account!',
				metadata: 'aGVsbG8='
			}]
		})],
		/* V2: set info with default permissions on a token account */
		['v2-setinfo-default-permission', await buildBlock({
			account: token,
			signer: tokenOwner,
			previous: BlockHash.getAccountOpeningHash(token),
			operations: [{
				type: Operations.OperationType.SET_INFO,
				name: 'MY_TOKEN',
				description: 'A token',
				metadata: '',
				defaultPermission: new Permissions(['ACCESS'])
			}]
		})],
		/* V2: modify permissions (SET, account principal) */
		['v2-modifypermissions', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.MODIFY_PERMISSIONS,
				principal: signerB,
				method: AdjustMethod.SET,
				permissions: new Permissions(['ACCESS', 'UPDATE_INFO'])
			}]
		})],
		/* V2: modify permissions clearing (null permissions) */
		['v2-modifypermissions-clear', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.MODIFY_PERMISSIONS,
				principal: signerB,
				method: AdjustMethod.SET,
				permissions: null
			}]
		})],
		/* V2: modify permissions with certificate principal */
		['v2-modifypermissions-cert', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.MODIFY_PERMISSIONS,
				principal: {
					usingCertificate: true,
					certificateHash: new CertificateHash(Buffer.alloc(32, 0x77).toString('hex')),
					certificateAccount: signerB
				},
				method: AdjustMethod.SET,
				permissions: new Permissions(['ACCESS'])
			}]
		})],
		/* V2: create token identifier on the opening block */
		['v2-createidentifier', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.CREATE_IDENTIFIER,
				identifier: createdToken
			}]
		})],
		/* V2: create multisig identifier with arguments */
		['v2-createidentifier-multisig', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: prevHash,
			operations: [{
				type: Operations.OperationType.CREATE_IDENTIFIER,
				identifier: createdMultisig,
				createArguments: {
					type: AccountKeyAlgorithm.MULTISIG,
					signers: [signerB, signerC],
					quorum: 2n
				}
			}]
		})],
		/* V2: token admin supply (token account, delegate signer) */
		['v2-tokenadminsupply', await buildBlock({
			account: token,
			signer: tokenOwner,
			previous: BlockHash.getAccountOpeningHash(token),
			operations: [{
				type: Operations.OperationType.TOKEN_ADMIN_SUPPLY,
				amount: 1000000n,
				method: AdjustMethod.ADD
			}]
		})],
		/* V2: token admin modify balance */
		['v2-tokenadminmodifybalance', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.TOKEN_ADMIN_MODIFY_BALANCE,
				token,
				amount: 42n,
				method: AdjustMethod.SUBTRACT
			}]
		})],
		/* V2: manage certificate removal by hash */
		['v2-managecert-subtract', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.MANAGE_CERTIFICATE,
				method: AdjustMethod.SUBTRACT,
				certificateOrHash: new CertificateHash(Buffer.alloc(32, 0x42).toString('hex'))
			}]
		})],
		/* V2: manage certificate addition with a real self-signed certificate */
		['v2-managecert-add', await buildBlock({
			account: signerA,
			signer: signerA,
			previous: openingA,
			operations: [{
				type: Operations.OperationType.MANAGE_CERTIFICATE,
				method: AdjustMethod.ADD,
				certificateOrHash: certificate,
				intermediateCertificates: null
			}]
		})],
		/* V2: nested multisig signer tree with multiple signatures */
		['v2-multisig-signers', await buildBlock({
			account: signerA,
			signer: [multisigAddr, [
				signerB,
				[multisigNested, [signerC, signerD]],
				signerA
			]],
			previous: openingA,
			operations: [send]
		})],
		/* V2: storage account delegating (SET_REP allowed for storage) */
		['v2-setrep-storage', await buildBlock({
			account: storage,
			signer: tokenOwner,
			previous: BlockHash.getAccountOpeningHash(storage),
			operations: [{ type: Operations.OperationType.SET_REP, to: signerB }]
		})]
	];

	const fixtures = cases.map(function([name, { block, unsignedBytes }]) {
		let subnet: string | null = null;
		if (block.subnet !== undefined) {
			subnet = block.subnet.toString();
		}

		let idempotent: string | null = null;
		if (block.idempotent !== undefined) {
			idempotent = block.idempotent.toString('hex').toUpperCase();
		}

		return({
			name,
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase(),
			unsigned_bytes: unsignedBytes,
			hash: block.hash.toString(),
			version: block.version,
			purpose: block.purpose,
			network: block.network.toString(),
			subnet,
			idempotent,
			date_ms: block.date.getTime(),
			account: block.account.publicKeyString.get(),
			previous: block.previous.toString(),
			operation_count: block.operations.length,
			signature_count: block.signatures.length,
			signatures: block.signatures.map(function(signature) {
				return(signature.toString('hex').toUpperCase());
			})
		});
	});

	fs.mkdirSync(path.dirname(outFile), { recursive: true });
	fs.writeFileSync(outFile, JSON.stringify(fixtures, null, '\t') + '\n');
	console.log(`Wrote ${fixtures.length} fixtures to ${outFile}`);
}

main().catch(function(error: unknown) {
	console.error(error);
	process.exit(1);
});
