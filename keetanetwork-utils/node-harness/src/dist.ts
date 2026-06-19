/*
 * Shared resolution of the reference implementation `dist` directory.
 */

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
 * Resolve a caller-supplied output path and confine it to a permitted base
 * (the current working directory or the OS temp directory), rejecting
 * traversal outside those bases before any file access.
 */
export function resolveOutputPath(argument: string | undefined, usage: string): string {
	if (argument === undefined) {
		console.error(usage);
		process.exit(1);
	}

	const resolved = path.resolve(argument);
	const allowedBases = [path.resolve(process.cwd()), path.resolve(os.tmpdir())];
	const permitted = allowedBases.some(function(base) {
		return(resolved === base || resolved.startsWith(base + path.sep));
	});

	if (!permitted) {
		console.error(`refusing to write outside permitted directories: ${argument}`);
		process.exit(1);
	}

	return(resolved);
}

export function loadModule<T>(dist: string, relative: string): T {
	/* The dist directory is only known at runtime, so a dynamic require is unavoidable */
	// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/consistent-type-assertions
	return(require(path.join(dist, relative)) as T);
}
