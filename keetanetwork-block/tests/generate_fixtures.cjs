#!/usr/bin/env node
'use strict';

/*
 * Generates the checked-in block wire fixtures from the reference
 * TypeScript implementation.
 *
 * Usage: node tests/generate_fixtures.cjs [path-to-node-dist-src] [output-json]
 *
 * Output: tests/fixtures/blocks.json
 */

const fs = require('fs');
const path = require('path');

const distSrc = process.argv[2] ?? path.join(
	__dirname, '..', '..', 'keetanetwork-utils', 'node-harness',
	'node_modules', '@keetanetwork', 'keetanet-node', 'dist'
);

const { Account, AccountKeyAlgorithm } = require(path.join(distSrc, 'lib/account.js'));
const BlockModule = require(path.join(distSrc, 'lib/block/index.js'));
const { UnsignedBlock, Block, BlockHash, BlockPurpose, AdjustMethod } = BlockModule;
const { Permissions, BasePermissionTypes } = require(path.join(distSrc, 'lib/permissions.js'));
const { CertificateHash, CertificateBuilder } = require(path.join(distSrc, 'lib/utils/certificate.js'));
const Operations = require(path.join(distSrc, 'lib/block/operations.js'));

const SEED = Buffer.alloc(32, 0x5a).toString('hex');

function account(index, algorithm) {
	return Account.fromSeed(SEED, index, algorithm ?? AccountKeyAlgorithm.ED25519);
}

const DATE_MS = new Date('2025-06-01T12:34:56.789Z');
const DATE_PLAIN = new Date('2025-06-01T12:34:56.000Z');
const OLD_DATE = new Date('2024-01-02T03:04:05.500Z');
const NETWORK = 0n;

async function buildBlock(input) {
	const unsigned = new UnsignedBlock({
		network: NETWORK,
		date: DATE_MS,
		purpose: BlockPurpose.GENERIC,
		version: 2,
		...input
	});

	const unsignedBytes = Buffer.from(unsigned.toBytes(false)).toString('hex').toUpperCase();
	const block = await unsigned.seal();
	return { block, unsignedBytes };
}

async function main() {
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

	const send = {
		type: Operations.OperationType.SEND,
		to: signerB,
		amount: 1000n,
		token
	};

	const cases = [];

	/* V1: signer == account (account encodes as NULL), subnet absent (NULL) */
	cases.push(['v1-basic', await buildBlock({
		version: 1,
		purpose: undefined,
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [send]
	})]);

	/* V1: subnet + idempotent + signer != account + explicit previous */
	cases.push(['v1-full', await buildBlock({
		version: 1,
		purpose: undefined,
		account: signerB,
		signer: signerA,
		subnet: 0x1234n,
		idempotent: Buffer.from('0102030405060708090a0b0c', 'hex'),
		previous: prevHash,
		operations: [send],
		date: DATE_PLAIN
	})]);

	/* V2: send with external, signer == account (NULL signer) */
	cases.push(['v2-send-external', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{ ...send, external: 'payment ref 42' }]
	})]);

	/* V2: send with empty external string */
	cases.push(['v2-send-external-empty', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{ ...send, external: '' }]
	})]);

	/* V2: negative amount allowed before the numeric cutoff */
	cases.push(['v2-send-negative-olddate', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		date: OLD_DATE,
		operations: [{ ...send, amount: -5n }]
	})]);

	/* V2: subnet + idempotent + distinct signer */
	cases.push(['v2-full-header', await buildBlock({
		account: signerB,
		signer: signerA,
		subnet: 99n,
		idempotent: Buffer.from('00ff00ff', 'hex'),
		previous: prevHash,
		operations: [send]
	})]);

	/* V2: FEE purpose (SEND only) */
	cases.push(['v2-fee', await buildBlock({
		purpose: BlockPurpose.FEE,
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [send]
	})]);

	/* V2: receive with forward + exact */
	cases.push(['v2-receive-forward', await buildBlock({
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
	})]);

	/* V2: receive without forward */
	cases.push(['v2-receive-plain', await buildBlock({
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
	})]);

	/* V2: set rep */
	cases.push(['v2-setrep', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{ type: Operations.OperationType.SET_REP, to: signerB }]
	})]);

	/* V2: set info without default permissions */
	cases.push(['v2-setinfo', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.SET_INFO,
			name: 'MY_ACCOUNT',
			description: 'A test account!',
			metadata: 'aGVsbG8='
		}]
	})]);

	/* V2: set info with default permissions on a token account */
	cases.push(['v2-setinfo-default-permission', await buildBlock({
		account: token,
		signer: tokenOwner,
		previous: BlockHash.getAccountOpeningHash(token),
		operations: [{
			type: Operations.OperationType.SET_INFO,
			name: 'MY_TOKEN',
			description: 'A token',
			metadata: '',
			defaultPermission: new Permissions([ 'ACCESS' ])
		}]
	})]);

	/* V2: modify permissions (SET, account principal) */
	cases.push(['v2-modifypermissions', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.MODIFY_PERMISSIONS,
			principal: signerB,
			method: AdjustMethod.SET,
			permissions: new Permissions([ 'ACCESS', 'UPDATE_INFO' ])
		}]
	})]);

	/* V2: modify permissions clearing (null permissions) */
	cases.push(['v2-modifypermissions-clear', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.MODIFY_PERMISSIONS,
			principal: signerB,
			method: AdjustMethod.SET,
			permissions: null
		}]
	})]);

	/* V2: modify permissions with certificate principal */
	cases.push(['v2-modifypermissions-cert', await buildBlock({
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
			permissions: new Permissions([ 'ACCESS' ])
		}]
	})]);

	/* V2: create token identifier on the opening block */
	const createdToken = signerA.generateIdentifier(AccountKeyAlgorithm.TOKEN, openingA, 0);
	cases.push(['v2-createidentifier', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.CREATE_IDENTIFIER,
			identifier: createdToken
		}]
	})]);

	/* V2: create multisig identifier with arguments */
	const createdMultisig = signerA.generateIdentifier(AccountKeyAlgorithm.MULTISIG, prevHash, 0);
	cases.push(['v2-createidentifier-multisig', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: prevHash,
		operations: [{
			type: Operations.OperationType.CREATE_IDENTIFIER,
			identifier: createdMultisig,
			createArguments: {
				type: AccountKeyAlgorithm.MULTISIG,
				signers: [ signerB, signerC ],
				quorum: 2n
			}
		}]
	})]);

	/* V2: token admin supply (token account, delegate signer) */
	cases.push(['v2-tokenadminsupply', await buildBlock({
		account: token,
		signer: tokenOwner,
		previous: BlockHash.getAccountOpeningHash(token),
		operations: [{
			type: Operations.OperationType.TOKEN_ADMIN_SUPPLY,
			amount: 1000000n,
			method: AdjustMethod.ADD
		}]
	})]);

	/* V2: token admin modify balance */
	cases.push(['v2-tokenadminmodifybalance', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.TOKEN_ADMIN_MODIFY_BALANCE,
			token,
			amount: 42n,
			method: AdjustMethod.SUBTRACT
		}]
	})]);

	/* V2: manage certificate removal by hash */
	cases.push(['v2-managecert-subtract', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.MANAGE_CERTIFICATE,
			method: AdjustMethod.SUBTRACT,
			certificateOrHash: new CertificateHash(Buffer.alloc(32, 0x42).toString('hex'))
		}]
	})]);

	/* V2: manage certificate addition with a real self-signed certificate */
	const certificate = await new CertificateBuilder({
		issuer: signerA,
		validFrom: new Date('2025-01-01T00:00:00.000Z'),
		validTo: new Date('2035-01-01T00:00:00.000Z')
	}).build({
		serial: 1,
		subjectPublicKey: signerA
	});
	cases.push(['v2-managecert-add', await buildBlock({
		account: signerA,
		signer: signerA,
		previous: openingA,
		operations: [{
			type: Operations.OperationType.MANAGE_CERTIFICATE,
			method: AdjustMethod.ADD,
			certificateOrHash: certificate,
			intermediateCertificates: null
		}]
	})]);

	/* V2: nested multisig signer tree with multiple signatures */
	cases.push(['v2-multisig-signers', await buildBlock({
		account: signerA,
		signer: [ multisigAddr, [
			signerB,
			[ multisigNested, [ signerC, signerD ] ],
			signerA
		]],
		previous: openingA,
		operations: [send]
	})]);

	/* V2: storage account delegating (SET_REP allowed for storage) */
	cases.push(['v2-setrep-storage', await buildBlock({
		account: storage,
		signer: tokenOwner,
		previous: BlockHash.getAccountOpeningHash(storage),
		operations: [{ type: Operations.OperationType.SET_REP, to: signerB }]
	})]);

	const fixtures = cases.map(function([name, { block, unsignedBytes }]) {
		return {
			name,
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase(),
			unsigned_bytes: unsignedBytes,
			hash: block.hash.toString(),
			version: block.version,
			purpose: block.purpose,
			network: block.network.toString(),
			subnet: block.subnet === undefined ? null : block.subnet.toString(),
			idempotent: block.idempotent === undefined ? null : block.idempotent.toString('hex').toUpperCase(),
			date_ms: block.date.getTime(),
			account: block.account.publicKeyString.get(),
			previous: block.previous.toString(),
			operation_count: block.operations.length,
			signature_count: block.signatures.length,
			signatures: block.signatures.map((s) => s.toString('hex').toUpperCase())
		};
	});

	const outFile = process.argv[3] ?? path.join(__dirname, 'fixtures', 'blocks.json');
	fs.mkdirSync(path.dirname(outFile), { recursive: true });
	fs.writeFileSync(outFile, JSON.stringify(fixtures, null, '\t') + '\n');
	console.log(`Wrote ${fixtures.length} fixtures to ${outFile}`);
}

main().catch(function(error) {
	console.error(error);
	process.exit(1);
});
