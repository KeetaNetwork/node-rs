// End-to-end through Node.js: a JavaScript host answers the engine's reads
// asynchronously, the way a node reading its ledger database does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { setImmediate as tick } from 'node:timers/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { ContractEngine } = require('../index.js');

const here = dirname(fileURLToPath(import.meta.url));
const contracts = join(here, '../../keetanetwork-contract-engine/tests/contracts');

/** An example contract's sBPF ELF, built with Solana's platform tools. */
function elf(name) {
	const path = join(contracts, 'target/deploy', `${name}.so`);
	if (!existsSync(path)) {
		const tool = process.env.CARGO_BUILD_SBF ?? join(homedir(), '.local/share/solana/install/active_release/bin/cargo-build-sbf');
		execFileSync(tool, ['--arch', 'v3', '--manifest-path', join(contracts, 'keeta-probe/Cargo.toml'), '--', '--locked'], { cwd: contracts, stdio: 'inherit' });
	}
	return readFileSync(path);
}

// An Ed25519 account from the engine's Rust tests (seed 1), and a storage
// account and token derived from another key.
const ALICE = 'keeta_afn6fkoeegzkvxcxhwvqyts7opvmfnfcqukr2ilirjkx2v4psgb3gyeyb2vms';
const PROBE = 'keeta_asinue67gy4sgwf3m3bsnqax4wpmg2b4z7b5geuiaz7dt53r33t5ok3sbljvc';
const TOKEN = 'keeta_aoinue67gy4sgwf3m3bsnqax4wpmg2b4z7b5geuiaz7dt53r33t5ovl6dqkvg';
const TIME = 1_767_225_600_000;

const b64 = (buffer) => Buffer.from(buffer).toString('base64');
const unb64 = (text) => Buffer.from(text, 'base64');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const u128 = (value) => {
	const bytes = Buffer.alloc(16);
	bytes.writeBigUInt64LE(BigInt(value) & 0xffff_ffff_ffff_ffffn);
	bytes.writeBigUInt64LE(BigInt(value) >> 64n, 8);
	return bytes;
};
const string = (text) => {
	const bytes = Buffer.from(text);
	const length = Buffer.alloc(4);
	length.writeUInt32LE(bytes.length);
	return Buffer.concat([length, bytes]);
};

// The probe contract's instructions, borsh-encoded: a variant index, then
// its fields (see tests/contracts/keeta-probe).
const probe = {
	increment: (index) => Buffer.from([0, index]),
	forceWrite: (index) => Buffer.from([1, index]),
	echo: () => Buffer.from([5]),
	fail: (message) => Buffer.concat([Buffer.from([8]), string(message)]),
	/** `to` and `token` in the 34-byte form contracts see */
	send: (to, token, amount) => Buffer.concat([Buffer.from([9]), to, token, u128(amount)]),
	setInfo: (name, description, metadata) => Buffer.concat([Buffer.from([10]), string(name), string(description), string(metadata)])
};

const COUNTER = sha256('counter');

/** A ledger in JavaScript, answering asynchronously. */
class MemoryHost {
	code = new Map();
	contracts = new Map();
	/** contract → Map(hex account id → base64 data) */
	storage = new Map();
	/** `${account}/${token}` → bigint */
	balances = new Map();
	requests = [];
	failOn = null;

	callback = async (text) => {
		const request = JSON.parse(text);
		this.requests.push(request.op);
		await tick(); // answer on a later turn of the event loop
		if (request.op === this.failOn) {
			throw new Error('database unreachable');
		}
		return JSON.stringify(this.answer(request));
	};

	deploy(address, code) {
		const codeHash = sha256(code);
		this.code.set(codeHash, b64(code));
		this.contracts.set(address, { address, codeHash, info: { name: '', description: '', metadata: '' } });
	}

	contractStorage(contract) {
		if (!this.storage.has(contract)) {
			this.storage.set(contract, new Map());
		}
		return this.storage.get(contract);
	}

	balance(account, token) {
		return this.balances.get(`${account}/${token}`) ?? 0n;
	}

	answer(request) {
		switch (request.op) {
			case 'codeBytes':
				return this.code.get(request.checksum) ?? null;
			case 'contract':
				return this.contracts.get(request.address) ?? null;
			case 'storageGet':
				return this.contractStorage(request.contract).get(unb64(request.key).toString('hex')) ?? null;
			case 'balance':
				return this.balance(request.account, request.token).toString();
			case 'tokenSupply':
				return null;
			case 'sendRefusal':
				return null;
			default:
				throw new Error(`unknown op ${request.op}`);
		}
	}

	/** What the ledger does once the call's block is accepted. */
	apply(call, outcome) {
		const move = (from, to, token, amount) => {
			this.balances.set(`${from}/${token}`, this.balance(from, token) - BigInt(amount));
			this.balances.set(`${to}/${token}`, this.balance(to, token) + BigInt(amount));
		};
		for (const fund of call.funds ?? []) {
			move(call.caller, call.instruction.contract, fund.token, fund.amount);
		}
		for (const write of outcome.writes) {
			const storage = this.contractStorage(write.owner);
			if (write.data === null) {
				storage.delete(write.id);
			} else {
				storage.set(write.id, write.data);
			}
		}
		for (const effect of outcome.effects) {
			if (effect.kind === 'send') {
				move(effect.from, effect.to, effect.token, effect.amount);
			} else {
				this.contracts.get(effect.account).info = { name: effect.name, description: effect.description, metadata: effect.metadata };
			}
		}
	}
}

function setup() {
	const host = new MemoryHost();
	const engine = new ContractEngine(JSON.stringify({ network: 0 }), host.callback);
	return { host, engine };
}

const ok = (text) => {
	const outcome = JSON.parse(text);
	assert.ok('ok' in outcome, `expected ok, got ${text}`);
	return outcome.ok;
};

const call = (accounts, data, funds = []) => ({
	caller: ALICE,
	instruction: { contract: PROBE, accounts, data: b64(data) },
	funds,
	gasLimit: '1400000',
	timeMillis: TIME
});

/** Store the probe's code and deploy it at `PROBE`. */
async function deployProbe(world) {
	const code = elf('keeta_probe');
	const stored = ok(await world.engine.storeCode(code));
	world.host.deploy(PROBE, code);
	return stored;
}

/** Run a call and apply its outcome. */
async function run(world, request) {
	const outcome = ok(await world.engine.runLedgerCall(JSON.stringify(request)));
	world.host.apply(request, outcome);
	return outcome;
}

test('runs a contract with its state held in JavaScript', async () => {
	const world = setup();
	const stored = await deployProbe(world);
	assert.equal(stored.checksum, sha256(elf('keeta_probe')));

	const counter = [{ owner: PROBE, id: COUNTER, writable: true }];
	for (const expected of [1n, 2n]) {
		const outcome = await run(world, call(counter, probe.increment(0)));
		assert.deepEqual(outcome.events, [{ contract: PROBE, attributes: [['counter', String(expected)]] }]);
		assert.deepEqual(outcome.reads.map((read) => read.id), [COUNTER]);
		assert.equal(outcome.writes.length, 1);
		assert.equal(unb64(outcome.writes[0].data).readBigUInt64LE(), expected);
		assert.ok(BigInt(outcome.gasUsed) > 0n);
	}
	assert.ok(!world.host.requests.includes('codeBytes'), 'stored code stays loaded');

	// A new engine loads the code from the host.
	const restarted = new ContractEngine(JSON.stringify({ network: 0 }), world.host.callback);
	ok(await restarted.runLedgerCall(JSON.stringify(call(counter, probe.increment(0)))));
	assert.ok(world.host.requests.includes('codeBytes'));
});

test('a contract\'s sends and account info are the call\'s effects', async () => {
	const world = setup();
	await deployProbe(world);
	world.host.balances.set(`${ALICE}/${TOKEN}`, 10n);

	// The probe echoes its caller and its funds, in the form contracts see addresses in.
	const echoed = await run(world, call([], probe.echo(), [{ token: TOKEN, amount: '7' }]));
	const echo = unb64(echoed.data);
	const alice = echo.subarray(0, 34);
	const token = echo.subarray(34 + 34 + 8 + 4, 34 + 34 + 8 + 4 + 34);
	assert.equal(world.host.balance(PROBE, TOKEN), 7n);
	assert.deepEqual(echoed.effects, []);

	const paid = await run(world, call([], probe.send(alice, token, 5)));
	assert.deepEqual(paid.effects, [{ kind: 'send', from: PROBE, to: ALICE, token: TOKEN, amount: '5', external: null }]);
	assert.equal(world.host.balance(ALICE, TOKEN), 8n);

	const named = await run(world, call([], probe.setInfo('PROBE', 'A probe', '')));
	assert.deepEqual(named.effects, [{ kind: 'setInfo', account: PROBE, name: 'PROBE', description: 'A probe', metadata: '' }]);
});

test('engine failures are outcomes, host failures abort the call', async () => {
	const world = setup();
	await deployProbe(world);

	const missing = JSON.parse(await world.engine.runLedgerCall(JSON.stringify({ ...call([], probe.echo()), instruction: { contract: TOKEN, accounts: [], data: b64(probe.echo()) } })));
	assert.equal(missing.error.kind, 'unknownContract');

	const failed = JSON.parse(await world.engine.runLedgerCall(JSON.stringify(call([], probe.fail('nope')))));
	assert.deepEqual(failed.error, { kind: 'contract', message: 'contract: nope' });

	await run(world, call([{ owner: PROBE, id: COUNTER, writable: true }], probe.increment(0)));
	const readonly = [{ owner: PROBE, id: COUNTER, writable: false }];
	const refused = JSON.parse(await world.engine.runLedgerCall(JSON.stringify(call(readonly, probe.forceWrite(0)))));
	assert.equal(refused.error.kind, 'invalidAccount');

	world.host.failOn = 'storageGet';
	const unreachable = JSON.parse(await world.engine.runLedgerCall(JSON.stringify(call(readonly, probe.echo()))));
	assert.equal(unreachable.error.kind, 'host');
	assert.match(unreachable.error.message, /database unreachable/);

	const small = new ContractEngine(JSON.stringify({ network: 0, maxCodeSize: 16 }), world.host.callback);
	const tooLarge = JSON.parse(await small.storeCode(elf('keeta_probe')));
	assert.equal(tooLarge.error.kind, 'codeTooLarge');

	// Malformed input rejects: bad JSON, a call without its gas limit, an unknown setting.
	await assert.rejects(world.engine.runLedgerCall('not json'), /bad ledger call/);
	const { gasLimit: _, ...withoutGas } = call([], probe.echo());
	await assert.rejects(world.engine.runLedgerCall(JSON.stringify(withoutGas)), /gasLimit/);
	assert.throws(() => new ContractEngine(JSON.stringify({ network: 0, sequencer: ALICE }), world.host.callback), /unknown field/);
});

test('calls run concurrently without blocking the event loop', async () => {
	const world = setup();
	await deployProbe(world);
	const outcomes = await Promise.all(
		Array.from({ length: 8 }, () => world.engine.runLedgerCall(JSON.stringify(call([], probe.echo()))))
	);
	const data = outcomes.map(ok).map((outcome) => {
		assert.deepEqual(outcome.logs, [{ contract: PROBE, message: 'echo' }]);
		return outcome.data;
	});
	assert.equal(new Set(data).size, 1);
});
