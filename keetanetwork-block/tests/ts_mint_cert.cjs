#!/usr/bin/env node
'use strict';

/*
 * Mints a deterministic X.509 certificate for a given subject account
 * using the reference TypeScript implementation.
 *
 * Usage: node tests/ts_mint_cert.cjs <path-to-node-dist-src> <subject-public-key-string>
 *
 * Output: the certificate DER as uppercase hex on stdout.
 */

const path = require('path');

const distSrc = process.argv[2];
const subjectPublicKey = process.argv[3];

if (distSrc === undefined || subjectPublicKey === undefined) {
	console.error('Usage: node tests/ts_mint_cert.cjs <path-to-node-dist-src> <subject-public-key-string>');
	process.exit(1);
}

const { Account, AccountKeyAlgorithm } = require(path.join(distSrc, 'lib/account.js'));
const { CertificateBuilder } = require(path.join(distSrc, 'lib/utils/certificate.js'));

const ISSUER_SEED = Buffer.alloc(32, 0x77).toString('hex');

async function main() {
	const issuer = Account.fromSeed(ISSUER_SEED, 0, AccountKeyAlgorithm.ED25519);
	const subject = Account.fromPublicKeyString(subjectPublicKey);

	const certificate = await new CertificateBuilder({
		issuer,
		validFrom: new Date('2025-01-01T00:00:00.000Z'),
		validTo: new Date('2035-01-01T00:00:00.000Z')
	}).build({
		serial: 7,
		subjectPublicKey: subject
	});

	process.stdout.write(Buffer.from(certificate.toDER()).toString('hex').toUpperCase() + '\n');
}

main().catch(function(error) {
	console.error(error);
	process.exit(1);
});
