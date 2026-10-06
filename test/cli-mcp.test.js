import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { handle } from '../src/mcp.js';

const BIN = fileURLToPath(new URL('../bin/pfencrypt.js', import.meta.url));
const run = (args, opts = {}) => execFileSync(process.execPath, [BIN, ...args], { encoding: 'utf8', ...opts });

test('CLI: keygen, encrypt a file, decrypt it back', () => {
	const dir = mkdtempSync(join(tmpdir(), 'pfencrypt-'));
	run(['keygen', '--out', join(dir, 'alice')]);
	if (process.platform !== 'win32') assert.equal(statSync(join(dir, 'alice.key')).mode & 0o777, 0o600);

	writeFileSync(join(dir, 'msg.txt'), 'meet at 9');
	const sealed = run(['encrypt', '--to', join(dir, 'alice.pub'), join(dir, 'msg.txt')]);
	assert.equal(JSON.parse(sealed).alg, 'ML-KEM-1024');
	writeFileSync(join(dir, 'msg.enc'), sealed);

	assert.equal(run(['decrypt', '--key', join(dir, 'alice.key'), join(dir, 'msg.enc')]), 'meet at 9');
	// stdin, with the key from the environment
	assert.equal(
		run(['decrypt'], { input: sealed, env: { ...process.env, PFENCRYPT_KEY: readFileSync(join(dir, 'alice.key'), 'utf8') } }),
		'meet at 9',
	);
});

test('MCP: lists tools, encrypts, and decrypts with the key from the environment only', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'pfencrypt-mcp-'));
	const list = await handle({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
	assert.deepEqual(list.result.tools.map((t) => t.name), ['encrypt', 'decrypt', 'generate_keypair', 'list_algorithms']);
	// decrypt takes no private key argument at all
	assert.ok(!('private_key' in list.result.tools[1].inputSchema.properties));

	const gen = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'generate_keypair', arguments: { path: join(dir, 'k') } } });
	const { publicKey } = JSON.parse(gen.result.content[0].text);
	assert.ok(!gen.result.content[0].text.includes(readFileSync(join(dir, 'k.key'), 'utf8').trim()), 'the private key is not returned');

	const enc = await handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'encrypt', arguments: { text: 'hi agent', public_key: publicKey } } });
	const envelope = enc.result.content[0].text;

	const env = { PFENCRYPT_KEY: readFileSync(join(dir, 'k.key'), 'utf8') };
	const dec = await handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'decrypt', arguments: { envelope } } }, env);
	assert.equal(dec.result.content[0].text, 'hi agent');

	const noKey = await handle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'decrypt', arguments: { envelope } } }, {});
	assert.equal(noKey.result.isError, true);
});
