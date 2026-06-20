/*
 * Reads hex-encoded block bytes (one per line) on stdin, parses each with
 * the reference TypeScript implementation and writes one JSON line per
 * block: { hash, bytes } where bytes is the re-serialized hex.
 *
 * Usage: node dist/ts_verify.js <path-to-node-dist>
 */

import type * as BlockModule from '@keetanetwork/keetanet-node/dist/lib/block/index';

import { loadModule, resolveDist } from './dist';

const dist = resolveDist(process.argv[2], 'usage: ts-verify.js <path-to-node-dist>');
const { Block } = loadModule<typeof BlockModule>(dist, 'lib/block/index.js');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', function(chunk: string) {
	input += chunk;
});

process.stdin.on('end', function() {
	for (const line of input.split('\n')) {
		const hexBytes = line.trim();
		if (hexBytes === '') {
			continue;
		}

		const buffer = Buffer.from(hexBytes, 'hex');
		const arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
		const block = new Block(arrayBuffer);

		console.log(JSON.stringify({
			hash: block.hash.toString(),
			bytes: Buffer.from(block.toBytes()).toString('hex').toUpperCase()
		}));
	}
});
