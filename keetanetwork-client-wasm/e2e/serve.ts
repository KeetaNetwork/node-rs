// Boots a real reference node via the shared harness, mints a base-token
// supply to the trusted account, then statically serves the wasm package and
// the e2e page so a browser can exercise the client against the live node.
// Playwright launches this as its `webServer`. On shutdown it stops the node.

import { spawn } from 'node:child_process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const harnessRoot = resolve(here, '../../keetanetwork-utils/node-harness');
const harnessScript = join(harnessRoot, 'dist/e2e_node.js');
const nodeDist = join(harnessRoot, 'node_modules/@keetanetwork/keetanet-node/dist');
const staticRoot = resolve(here, '..');

const PORT = Number(process.env.PORT ?? 5173);
const TRUSTED_SEED_HEX = '77'.repeat(32);
const MINT_AMOUNT = '1000000000';
const SEND_AMOUNT = '1000';

const MIME: Record<string, string> = {
	'.html': 'text/html',
	'.js': 'text/javascript',
	'.mjs': 'text/javascript',
	'.wasm': 'application/wasm',
	'.json': 'application/json',
};

interface HarnessResponse {
	api: string;
	network: string;
	baseToken: string;
	trusted: string;
	representative: string;
	[key: string]: unknown;
}

const harness = spawn('node', [harnessScript, nodeDist], { stdio: ['pipe', 'pipe', 'inherit'] });
const harnessStdout = harness.stdout;
const harnessStdin = harness.stdin;
if (harnessStdout === null || harnessStdin === null) {
	throw new Error('harness must expose stdin and stdout pipes');
}

const responses: HarnessResponse[] = [];
const waiters: ((response: HarnessResponse) => void)[] = [];
function deliver(): void {
	while (responses.length > 0 && waiters.length > 0) {
		const waiter = waiters.shift();
		const response = responses.shift();
		if (waiter !== undefined && response !== undefined) {
			waiter(response);
		}
	}
}

function nextResponse(): Promise<HarnessResponse> {
	return new Promise((resolveResponse) => {
		waiters.push(resolveResponse);
		deliver();
	});
}

function command(payload: Record<string, unknown>): void {
	harnessStdin.write(`${JSON.stringify(payload)}\n`);
}

createInterface({ input: harnessStdout }).on('line', (line: string) => {
	const trimmed = line.trim();
	if (trimmed.length > 0) {
		responses.push(JSON.parse(trimmed) as HarnessResponse);
		deliver();
	}
});

const ready = await nextResponse();
command({ cmd: 'init_supply', amount: MINT_AMOUNT });
await nextResponse();

const info = {
	api: ready.api,
	network: ready.network,
	baseToken: ready.baseToken,
	trusted: ready.trusted,
	recipient: ready.representative,
	trustedSeedHex: TRUSTED_SEED_HEX,
	amount: SEND_AMOUNT,
};

const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
	const path = (request.url ?? '/').split('?')[0];
	if (path === '/node-info.json') {
		response.setHeader('content-type', 'application/json');
		response.end(JSON.stringify(info));
		return;
	}

	const filePath = resolve(staticRoot, `.${path}`);
	if (!filePath.startsWith(staticRoot) || !existsSync(filePath)) {
		response.statusCode = 404;
		response.end('not found');
		return;
	}

	const body = await readFile(filePath);
	response.setHeader('content-type', MIME[extname(filePath)] ?? 'application/octet-stream');
	response.end(body);
});

server.listen(PORT, () => console.log(`e2e server on http://localhost:${PORT}`));

function shutdown(): void {
	try {
		command({ cmd: 'shutdown' });
	} catch {
		// The harness may already be gone; fall through to the kill below.
	}
	harness.kill('SIGTERM');
	server.close(() => process.exit(0));
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
