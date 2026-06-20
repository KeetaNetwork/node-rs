/*
 * Mints a deterministic X.509 certificate for a given subject account
 * using the reference TypeScript implementation.
 *
 * Usage: node dist/ts_mint_cert.js <path-to-node-dist> <subject-public-key-string>
 *
 * Output: the certificate DER as uppercase hex on stdout.
 */

import type * as AccountModule from '@keetanetwork/keetanet-node/dist/lib/account';
import type * as CertificateModule from '@keetanetwork/keetanet-node/dist/lib/utils/certificate';

import { loadModule, resolveDist } from './dist';

const USAGE = 'usage: ts-mint-cert.js <path-to-node-dist> <subject-public-key-string>';

const dist = resolveDist(process.argv[2], USAGE);
const subjectPublicKey = process.argv[3];
if (subjectPublicKey === undefined) {
	console.error(USAGE);
	process.exit(1);
}

const { Account, AccountKeyAlgorithm } = loadModule<typeof AccountModule>(dist, 'lib/account.js');
const { CertificateBuilder } = loadModule<typeof CertificateModule>(dist, 'lib/utils/certificate.js');

const ISSUER_SEED = Buffer.alloc(32, 0x77).toString('hex');

async function main(): Promise<void> {
	const issuer = Account.fromSeed(ISSUER_SEED, 0, AccountKeyAlgorithm.ED25519);
	const subject = Account.fromPublicKeyString(subjectPublicKey).assertKeyType(AccountKeyAlgorithm.ED25519);

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

main().catch(function(error: unknown) {
	console.error(error);
	process.exit(1);
});
