#!/usr/bin/env node
'use strict';

/*
 * Reads hex-encoded block bytes (one per line) on stdin, parses each with
 * the reference TypeScript implementation and writes one JSON line per
 * block: { hash, bytes } where bytes is the re-serialized hex.
 *
 * Usage: node tests/ts_verify.cjs <path-to-node-dist-src>
 */

const path = require('path');

const distSrc = process.argv[2];
if (!distSrc) {
	console.error('usage: ts_verify.cjs <path-to-node-dist-src>');
	process.exit(2);
}

const { Block } = require(path.join(distSrc, 'lib/block/index.js'));

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', function(chunk) {
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
