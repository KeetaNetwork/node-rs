/*
 * Shared resolution of the reference implementation `dist` directory.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as readline from 'node:readline';

export function resolveDist(argument: string | undefined, usage: string): string {
	if (argument === undefined) {
		console.error(usage);
		process.exit(2);
	}

	return(path.resolve(argument));
}

/*
 * Output writes are confined to the current working directory or the OS temp
 * directory. Anything resolving outside those bases is rejected as traversal.
 */
function allowedOutputBases(): string[] {
	return([path.resolve(process.cwd()), path.resolve(os.tmpdir())]);
}

/*
 * Resolve a caller-supplied output path and confine it to a permitted base,
 * rejecting traversal outside those bases before any file access.
 */
export function resolveOutputPath(argument: string | undefined, usage: string): string {
	if (argument === undefined) {
		console.error(usage);
		process.exit(1);
	}

	const resolved = path.resolve(argument);
	const permitted = allowedOutputBases().some(function(base) {
		return(resolved === base || resolved.startsWith(base + path.sep));
	});
	if (!permitted) {
		console.error(`refusing to write outside permitted directories: ${argument}`);
		process.exit(1);
	}

	return(resolved);
}

/*
 * Write to a caller-supplied output path, re-canonicalizing and validating the
 * path immediately before the filesystem access so the write can never escape
 * the permitted bases.
 */
export function writeOutputFile(outFile: string, contents: string): void {
	const resolved = path.resolve(outFile);
	const cwd = path.resolve(process.cwd());
	const tmp = path.resolve(os.tmpdir());
	const permitted =
		resolved === cwd || resolved.startsWith(cwd + path.sep) ||
		resolved === tmp || resolved.startsWith(tmp + path.sep);
	if (!permitted) {
		throw(new Error(`refusing to write outside permitted directories: ${outFile}`));
	}

	fs.mkdirSync(path.dirname(resolved), { recursive: true });
	fs.writeFileSync(resolved, contents);
}

/*
 * Decode a hex string into a standalone `ArrayBuffer`, copying out of the
 * pooled Node `Buffer` so the slice owns exactly the decoded bytes.
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
	const buffer = Buffer.from(hex, 'hex');
	return(buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength));
}

/*
 * Hex-encode any byte container the reference SDK hands back.
 */
export function toHex(buffer: ArrayBuffer | Buffer | Uint8Array): string {
	return(Buffer.from(buffer).toString('hex'));
}

/*
 * A request carries its command name in `cmd`; every other field is the
 * command's parameters.
 */
export interface DispatchRequest {
	cmd: string;
}

/*
 * Run the harness JSON-lines protocol
 */
export function runJsonLines(handler: (request: DispatchRequest) => Promise<unknown>): void {
	const rl = readline.createInterface({ input: process.stdin, terminal: false });

	let queue = Promise.resolve();
	rl.on('line', function(line) {
		if (line.trim() === '') {
			return;
		}

		queue = queue.then(async function() {
			try {
				// eslint-disable-next-line @typescript-eslint/consistent-type-assertions
				const request = JSON.parse(line) as DispatchRequest;
				const response = await handler(request);
				console.log(JSON.stringify(response));
			} catch (error) {
				console.error(error);

				let message = String(error);
				if (error instanceof Error) {
					message = error.message;
				}

				console.log(JSON.stringify({ error: message }));
			}
		});
	});
}

export function loadModule<T>(dist: string, relative: string): T {
	/*
	 * The dist directory is only known at runtime, so a dynamic require is unavoidable
	 */
	// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/consistent-type-assertions
	return(require(path.join(dist, relative)) as T);
}
