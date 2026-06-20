/*
 * Shared resolution of the reference implementation `dist` directory.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

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
	const permitted = allowedOutputBases().some(function(base) {
		return(resolved === base || resolved.startsWith(base + path.sep));
	});
	if (!permitted) {
		throw(new Error(`refusing to write outside permitted directories: ${outFile}`));
	}

	fs.mkdirSync(path.dirname(resolved), { recursive: true });
	fs.writeFileSync(resolved, contents);
}

/*
 * Read the harness stdin protocol - one hex-encoded element per line - and
 * invoke `handler` with each decoded `ArrayBuffer`, skipping blank lines.
 */
export function forEachHexLine(handler: (arrayBuffer: ArrayBuffer) => void): void {
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
			handler(arrayBuffer);
		}
	});
}

export function loadModule<T>(dist: string, relative: string): T {
	/* The dist directory is only known at runtime, so a dynamic require is unavoidable */
	// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/consistent-type-assertions
	return(require(path.join(dist, relative)) as T);
}
