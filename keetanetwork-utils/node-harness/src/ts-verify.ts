/*
 * Reads hex-encoded block bytes (one per line) on stdin, parses each with
 * the reference TypeScript implementation and writes one JSON line per
 * block: { hash, bytes } where bytes is the re-serialized hex.
 *
 * Usage: node dist/ts_verify.js <path-to-node-dist>
 */

import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';

import { forEachHexLine, loadModule, resolveDist } from './dist';

const dist = resolveDist(process.argv[2], 'usage: ts-verify.js <path-to-node-dist>');
const { Block } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');

forEachHexLine(function(arrayBuffer) {
	const block = new Block(arrayBuffer);

	console.log(JSON.stringify({
		hash: block.hash.toString(),
		bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase()
	}));
});
