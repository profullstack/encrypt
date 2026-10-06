/** Byte helpers that behave the same in Node, Bun, Deno and browsers. */

/** @param {number} n */
export function randomBytes(n) {
	return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** Standard base64 (with padding), as qrypt.chat writes it. @param {Uint8Array} bytes */
export function toBase64(bytes) {
	let binary = '';
	for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	return btoa(binary);
}

/** @param {string} text */
export function fromBase64(text) {
	if (typeof text !== 'string') throw new TypeError('expected a base64 string');
	const binary = atob(text.trim());
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}

/** Overwrite secrets in memory once they are no longer needed. @param {...Uint8Array} arrays */
export function wipe(...arrays) {
	for (const a of arrays) a?.fill?.(0);
}

/** Text or bytes in, bytes out. A Node Buffer becomes a plain Uint8Array. @param {string | Uint8Array} data */
export function toBytes(data) {
	if (typeof data === 'string') return new TextEncoder().encode(data);
	if (data instanceof Uint8Array) return Uint8Array.from(data);
	throw new TypeError('data must be a string or a Uint8Array');
}
