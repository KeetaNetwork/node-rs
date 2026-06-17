/*
 * Shared resolution of the reference implementation `dist` directory.
 */

import * as path from 'node:path';

export function resolveDist(argument: string | undefined, usage: string): string {
	if (argument === undefined) {
		console.error(usage);
		process.exit(2);
	}

	return(path.resolve(argument));
}

export function loadModule<T>(dist: string, relative: string): T {
	/* The dist directory is only known at runtime, so a dynamic require is unavoidable */
	// eslint-disable-next-line @typescript-eslint/no-require-imports, @typescript-eslint/consistent-type-assertions
	return(require(path.join(dist, relative)) as T);
}
