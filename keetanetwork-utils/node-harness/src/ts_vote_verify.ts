/*
 * Reads hex-encoded vote bytes (one per line) on stdin, parses each with
 * the reference TypeScript implementation and writes one JSON line per
 * vote: { hash, bytes, serial, issuer, blocks, validityFrom, validityTo,
 * fee?, quote? }.
 *
 * Usage: node dist/ts_vote_verify.js <path-to-node-dist>
 */

import type * as VoteModule from '@keetanetwork/keetanet-node/dist/lib/vote';

import { loadModule, resolveDist } from './dist';

const dist = resolveDist(process.argv[2], 'usage: ts_vote_verify.js <path-to-node-dist>');
const { Vote, VoteQuote } = loadModule<typeof VoteModule>(dist, 'lib/vote.js');

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
			// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
			return(serializeSingleFee(entry as SerializableFee));
		}));
	}
	if (fee === undefined) {
		return(undefined);
	}
	
	// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
	return(serializeSingleFee(fee as SerializableFee));
}

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

		/* `Vote` rejects quote=true certificates and `VoteQuote` rejects
		 * quote=false ones; try the regular shape first and fall back to
		 * the quote shape so the script handles both kinds without the
		 * caller having to know which it sent. */
		let vote: VoteModule.Vote | VoteModule.VoteQuote;
		try {
			vote = new Vote(arrayBuffer);
		} catch (error) {
			let code: string | undefined;
			if (error !== null && typeof error === 'object' && 'code' in error && typeof error.code === 'string') {
				code = error.code;
			}
			if (code !== 'VOTE_MALFORMED_FEES_QUOTE_INVALID') {
				throw(error);
			}
			vote = new VoteQuote(arrayBuffer);
		}

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

		console.log(JSON.stringify(result));
	}
});
