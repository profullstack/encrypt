/**
 * `pfencrypt mcp`: encrypt/decrypt as MCP tools over stdio (JSON-RPC 2.0, one
 * message per line).
 *
 * Private keys never pass through the model: decrypt reads the key from the
 * PFENCRYPT_KEY environment variable or a key file path, and generate_keypair
 * writes the private key to a file and returns only the public key.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { algorithms, decrypt, encrypt, generateKeyPair } from './index.js';

const VERSION = '0.1.0';

export const TOOLS = [
	{
		name: 'encrypt',
		description: "Encrypt text to a public key with quantum-resistant encryption (default: qrypt.chat's ML-KEM-1024 + ChaCha20-Poly1305). Returns a JSON envelope.",
		inputSchema: {
			type: 'object',
			properties: {
				text: { type: 'string', description: 'The plaintext' },
				public_key: { type: 'string', description: 'Recipient public key (base64)' },
				algorithm: { type: 'string', description: 'Optional; see list_algorithms' },
			},
			required: ['text', 'public_key'],
			additionalProperties: false,
		},
	},
	{
		name: 'decrypt',
		description: 'Decrypt an envelope with the private key from PFENCRYPT_KEY or key_file. The key itself is never an argument.',
		inputSchema: {
			type: 'object',
			properties: {
				envelope: { type: 'string', description: 'The JSON envelope (or its base64)' },
				key_file: { type: 'string', description: 'Optional path to a .key file; defaults to PFENCRYPT_KEY' },
			},
			required: ['envelope'],
			additionalProperties: false,
		},
	},
	{
		name: 'generate_keypair',
		description: 'Create a keypair: writes <path>.key (private, mode 0600) and <path>.pub, and returns only the public key.',
		inputSchema: {
			type: 'object',
			properties: {
				path: { type: 'string', description: 'File path prefix, e.g. ./alice' },
				algorithm: { type: 'string', description: 'Optional; see list_algorithms' },
			},
			required: ['path'],
			additionalProperties: false,
		},
	},
	{
		name: 'list_algorithms',
		description: 'List the available algorithms, the default first.',
		inputSchema: { type: 'object', properties: {}, additionalProperties: false },
	},
];

const text = (value) => ({ content: [{ type: 'text', text: value }] });

/** Run one tool. @param {string} name @param {any} args @param {NodeJS.ProcessEnv} env */
export async function callTool(name, args = {}, env = process.env) {
	switch (name) {
		case 'encrypt':
			return text(await encrypt(String(args.text), String(args.public_key), { algorithm: args.algorithm }));
		case 'decrypt': {
			const key = args.key_file ? readFileSync(args.key_file, 'utf8').trim() : env.PFENCRYPT_KEY?.trim();
			if (!key) throw new Error('No private key: set PFENCRYPT_KEY or pass key_file');
			return text(await decrypt(String(args.envelope), key));
		}
		case 'generate_keypair': {
			const pair = await generateKeyPair({ algorithm: args.algorithm });
			writeFileSync(`${args.path}.key`, `${pair.privateKey}\n`, { mode: 0o600 });
			writeFileSync(`${args.path}.pub`, `${pair.publicKey}\n`);
			return text(JSON.stringify({ algorithm: pair.algorithm, publicKey: pair.publicKey, privateKeyFile: `${args.path}.key` }));
		}
		case 'list_algorithms':
			return text(algorithms().join('\n'));
		default:
			throw new Error(`Unknown tool ${name}`);
	}
}

/** Answer one JSON-RPC request; undefined for notifications. */
export async function handle(message, env = process.env) {
	const { id, method, params } = message ?? {};
	const reply = (result) => ({ jsonrpc: '2.0', id, result });
	const fail = (code, msg) => ({ jsonrpc: '2.0', id, error: { code, message: msg } });
	if (id === undefined || id === null) return undefined;
	switch (method) {
		case 'initialize':
			return reply({
				protocolVersion: params?.protocolVersion ?? '2025-06-18',
				capabilities: { tools: {} },
				serverInfo: { name: '@profullstack/encrypt', version: VERSION },
			});
		case 'ping':
			return reply({});
		case 'tools/list':
			return reply({ tools: TOOLS });
		case 'tools/call':
			try {
				return reply(await callTool(params?.name, params?.arguments, env));
			} catch (error) {
				return reply({ ...text(error?.message ?? String(error)), isError: true });
			}
		default:
			return fail(-32601, `Method not found: ${method}`);
	}
}

export async function serve() {
	const rl = createInterface({ input: process.stdin });
	for await (const line of rl) {
		if (!line.trim()) continue;
		let message;
		try {
			message = JSON.parse(line);
		} catch {
			process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
			continue;
		}
		const response = await handle(message);
		if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
	}
}
