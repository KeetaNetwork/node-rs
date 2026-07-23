import { execSync } from 'node:child_process';

import { defineConfig, devices } from '@playwright/test';

// Binds both servers at once inside one child process so the two picks
// cannot collide with each other, then prints them space-separated.
const PICK_PORTS_SCRIPT =
	'const net = require("node:net");' +
	'const plain = net.createServer();' +
	'const fee = net.createServer();' +
	'plain.listen(0, () => fee.listen(0, () => {' +
	'console.log(plain.address().port, fee.address().port);' +
	'plain.close();' +
	'fee.close();' +
	'}));';

// Free ports picked once in the runner process and pinned through the
// environment: workers re-evaluate this module (fee.spec.ts imports it) but
// inherit the runner's environment, so every process agrees on the ports.
function reservedPorts(): number[] {
	if (process.env.KEETA_E2E_PORTS === undefined) {
		process.env.KEETA_E2E_PORTS = execSync(`node -e '${PICK_PORTS_SCRIPT}'`).toString().trim();
	}

	return process.env.KEETA_E2E_PORTS.split(' ').map(Number);
}

// The second port serves the fee-enforcing node (fee.spec.ts).
export const [PORT, FEE_PORT] = reservedPorts();
export const FEE_AMOUNT = '100';
const baseURL = `http://localhost:${PORT}`;

export default defineConfig({
	testDir: '.',
	timeout: 90_000,
	fullyParallel: false,
	reporter: 'list',
	use: {
		baseURL,
	},
	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] },
		},
	],
	webServer: [
		{
			command: 'node serve.ts',
			port: PORT,
			env: { PORT: String(PORT) },
			reuseExistingServer: false,
			timeout: 120_000,
			stdout: 'pipe',
			stderr: 'pipe',
		},
		{
			command: 'node serve.ts',
			port: FEE_PORT,
			env: { PORT: String(FEE_PORT), FEE: FEE_AMOUNT },
			reuseExistingServer: false,
			timeout: 120_000,
			stdout: 'pipe',
			stderr: 'pipe',
		},
	],
});
