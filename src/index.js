/**
 * @profullstack/encrypt: quantum-resistant encryption with qrypt.chat's scheme
 * as the default (ML-KEM-1024 + HKDF-SHA-256 + ChaCha20-Poly1305).
 *
 *   import { generateKeyPair, encrypt, decrypt } from '@profullstack/encrypt';
 *   const { publicKey, privateKey } = await generateKeyPair();
 *   const sealed = await encrypt('hello', publicKey);   // a JSON envelope string
 *   const text = await decrypt(sealed, privateKey);      // 'hello'
 *
 * Keys are base64 strings (raw ML-KEM key bytes), so they are the same keys
 * qrypt.chat stores and shows. More algorithms plug in with registerAlgorithm;
 * the envelope's `alg` picks the one that opens it.
 */

import { fromBase64, toBase64, toBytes } from './bytes.js';
import { ML_KEM_1024, ML_KEM_768 } from './qrypt-v3.js';

export const DEFAULT_ALGORITHM = 'ML-KEM-1024';

/** @type {Map<string, import('./index.d.ts').Algorithm>} */
const registry = new Map([
	[ML_KEM_1024.name, ML_KEM_1024],
	[ML_KEM_768.name, ML_KEM_768],
]);

/** Add (or replace) an algorithm. Its `name` is what envelopes carry as `alg`. */
export function registerAlgorithm(algorithm) {
	if (!algorithm?.name || typeof algorithm.encrypt !== 'function' || typeof algorithm.decrypt !== 'function' || typeof algorithm.generateKeyPair !== 'function') {
		throw new TypeError('an algorithm needs name, generateKeyPair, encrypt and decrypt');
	}
	registry.set(algorithm.name, algorithm);
}

/** Names of the algorithms available, the default first. */
export function algorithms() {
	return [DEFAULT_ALGORITHM, ...[...registry.keys()].filter((n) => n !== DEFAULT_ALGORITHM)];
}

function algorithm(name = DEFAULT_ALGORITHM) {
	const found = registry.get(name);
	if (!found) throw new Error(`Unknown algorithm "${name}". Known: ${algorithms().join(', ')}`);
	return found;
}

/** @param {string | Uint8Array} key */
function keyBytes(key) {
	return typeof key === 'string' ? fromBase64(key) : Uint8Array.from(key);
}

/**
 * A new keypair, both halves base64.
 * @param {{ algorithm?: string }} [options]
 */
export async function generateKeyPair({ algorithm: name = DEFAULT_ALGORITHM } = {}) {
	const { publicKey, privateKey } = await algorithm(name).generateKeyPair();
	return { algorithm: name, publicKey: toBase64(publicKey), privateKey: toBase64(privateKey) };
}

/**
 * Seal text or bytes to a public key. Returns the envelope as a JSON string.
 * @param {string | Uint8Array} data
 * @param {string | Uint8Array} publicKey base64 or raw bytes
 * @param {{ algorithm?: string }} [options]
 */
export async function encrypt(data, publicKey, { algorithm: name = DEFAULT_ALGORITHM } = {}) {
	return JSON.stringify(await algorithm(name).encrypt(toBytes(data), keyBytes(publicKey)));
}

/**
 * Read an envelope: a JSON string, base64 of that JSON (as qrypt.chat's
 * database returns it), or an already-parsed object.
 * @param {string | object} input
 */
export function parseEnvelope(input) {
	if (input && typeof input === 'object') return input;
	if (typeof input !== 'string') throw new TypeError('envelope must be a string or an object');
	const text = input.trim();
	let parsed;
	try {
		parsed = JSON.parse(text.startsWith('{') ? text : new TextDecoder().decode(fromBase64(text)));
	} catch {
		throw new Error('Not an encrypted envelope');
	}
	if (!parsed || typeof parsed !== 'object' || !parsed.alg) throw new Error('Not an encrypted envelope');
	return parsed;
}

/**
 * Open an envelope with a private key. Returns text (UTF-8) by default, or
 * bytes with { encoding: 'bytes' }. Throws if the key is wrong or the
 * envelope was tampered with.
 * @param {string | object} envelope
 * @param {string | Uint8Array} privateKey base64 or raw bytes
 * @param {{ encoding?: 'utf8' | 'bytes' }} [options]
 */
export async function decrypt(envelope, privateKey, { encoding = 'utf8' } = {}) {
	const parsed = parseEnvelope(envelope);
	let bytes;
	try {
		bytes = await algorithm(parsed.alg).decrypt(parsed, keyBytes(privateKey));
	} catch (error) {
		if (String(error?.message).startsWith('Unknown algorithm')) throw error;
		throw new Error('Could not decrypt: wrong key or a damaged envelope');
	}
	return encoding === 'bytes' ? bytes : new TextDecoder().decode(bytes);
}
