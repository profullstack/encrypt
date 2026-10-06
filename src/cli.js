/**
 * pfencrypt: the library from a shell.
 *
 *   pfencrypt keygen [--out name]           writes name.pub and name.key (0600)
 *   pfencrypt encrypt --to name.pub [file]  envelope to stdout (stdin when no file)
 *   pfencrypt decrypt --key name.key [file] plaintext to stdout
 *   pfencrypt algorithms
 *   pfencrypt mcp                           MCP server on stdio
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { algorithms, decrypt, encrypt, generateKeyPair } from './index.js';

const HELP = `pfencrypt: quantum-resistant encryption (default: qrypt.chat's ML-KEM-1024 + ChaCha20-Poly1305)

Usage:
  pfencrypt keygen [--out <name>] [--algorithm <alg>]   write <name>.pub and <name>.key (default: key)
  pfencrypt encrypt --to <file.pub | base64> [file]     seal a file (or stdin) to a public key
  pfencrypt decrypt --key <file.key | base64> [file]    open an envelope (or stdin) with a private key
  pfencrypt algorithms                                  list algorithms, the default first
  pfencrypt mcp                                         run as an MCP server on stdio

Keys are base64 text, the same keys qrypt.chat uses. Envelopes are JSON.
Set PFENCRYPT_KEY instead of --key to keep the private key off the command line.`;

/** @param {string[]} argv */
export function parseArgs(argv) {
	const flags = {};
	const rest = [];
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === '-h' || a === '--help') flags.help = true;
		else if (a.startsWith('--')) {
			const [k, v] = a.slice(2).split('=', 2);
			flags[k] = v ?? argv[++i];
		} else rest.push(a);
	}
	return { command: rest[0], args: rest.slice(1), flags };
}

/** A key given inline (base64) or as a file holding it. @param {string} value */
export function readKey(value) {
	if (!value) return undefined;
	if (/^[A-Za-z0-9+/=\s]{100,}$/.test(value)) return value.trim();
	return readFileSync(value, 'utf8').trim();
}

async function readInput(file) {
	if (file && file !== '-') return readFileSync(file);
	const chunks = [];
	for await (const chunk of process.stdin) chunks.push(chunk);
	return Buffer.concat(chunks);
}

/** @param {string[]} argv */
export async function main(argv = process.argv.slice(2)) {
	const { command, args, flags } = parseArgs(argv);
	if (!command || flags.help || command === 'help') {
		process.stdout.write(`${HELP}\n`);
		return;
	}
	switch (command) {
		case 'keygen': {
			const name = flags.out || 'key';
			const pair = await generateKeyPair({ algorithm: flags.algorithm });
			writeFileSync(`${name}.pub`, `${pair.publicKey}\n`);
			writeFileSync(`${name}.key`, `${pair.privateKey}\n`, { mode: 0o600 });
			process.stdout.write(`Wrote ${name}.pub and ${name}.key (${pair.algorithm}). Keep ${name}.key private.\n`);
			return;
		}
		case 'encrypt': {
			const to = readKey(flags.to);
			if (!to) throw new Error('encrypt needs --to <public key file or base64>');
			process.stdout.write(`${await encrypt(new Uint8Array(await readInput(args[0])), to, { algorithm: flags.algorithm })}\n`);
			return;
		}
		case 'decrypt': {
			const key = readKey(flags.key) ?? process.env.PFENCRYPT_KEY?.trim();
			if (!key) throw new Error('decrypt needs --key <private key file or base64> (or PFENCRYPT_KEY)');
			const bytes = await decrypt((await readInput(args[0])).toString('utf8'), key, { encoding: 'bytes' });
			process.stdout.write(bytes);
			return;
		}
		case 'algorithms':
			process.stdout.write(`${algorithms().join('\n')}\n`);
			return;
		case 'mcp': {
			const { serve } = await import('./mcp.js');
			await serve();
			return;
		}
		default:
			throw new Error(`Unknown command "${command}". Run pfencrypt --help.`);
	}
}
