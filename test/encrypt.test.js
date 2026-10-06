import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MlKem1024 } from 'mlkem';

import { DEFAULT_ALGORITHM, algorithms, decrypt, encrypt, generateKeyPair, parseEnvelope, registerAlgorithm } from '../src/index.js';
import { fromBase64, toBase64 } from '../src/bytes.js';

// A throwaway keypair and an envelope made by qrypt.chat's own
// PostQuantumEncryptionService.encryptForRecipient (qryptchat-web), checked
// there by its own decrypt. Test data only; the key protects nothing.
const fixture = JSON.parse(readFileSync(new URL('./qrypt-fixture.json', import.meta.url), 'utf8'));

test("the default is qrypt.chat's ML-KEM-1024", () => {
	assert.equal(DEFAULT_ALGORITHM, 'ML-KEM-1024');
	assert.equal(algorithms()[0], 'ML-KEM-1024');
	assert.ok(algorithms().includes('ML-KEM-768'));
});

test('round trip: text and bytes', async () => {
	const { publicKey, privateKey, algorithm } = await generateKeyPair();
	assert.equal(algorithm, 'ML-KEM-1024');
	assert.equal(fromBase64(publicKey).length, 1568);
	assert.equal(fromBase64(privateKey).length, 3168);

	const sealed = await encrypt('hello 🔐 world', publicKey);
	assert.equal(await decrypt(sealed, privateKey), 'hello 🔐 world');

	const bytes = new Uint8Array([0, 1, 2, 255, 254]);
	const out = await decrypt(await encrypt(bytes, publicKey), privateKey, { encoding: 'bytes' });
	assert.deepEqual([...out], [...bytes]);
});

test('the envelope has the qrypt.chat v3 shape and leaks no plaintext', async () => {
	const { publicKey } = await generateKeyPair();
	const env = JSON.parse(await encrypt('top secret', publicKey));
	assert.equal(env.v, 3);
	assert.equal(env.alg, 'ML-KEM-1024');
	assert.deepEqual(Object.keys(env).sort(), ['alg', 'c', 'kem', 'n', 's', 't', 'v']);
	assert.equal(fromBase64(env.s).length, 32, 'HKDF salt');
	assert.equal(fromBase64(env.n).length, 12, 'ChaCha20-Poly1305 nonce');
	assert.equal(fromBase64(env.c).length, 'top secret'.length + 16, 'ciphertext + Poly1305 tag');
	assert.ok(!JSON.stringify(env).includes('top secret'));
});

test('opens an envelope made by qrypt.chat itself', async () => {
	assert.equal(await decrypt(fixture.envelope, fixture.privateKey), fixture.plaintext);
});

test('qrypt.chat can open ours: same KEM key, same derivation (checked against the fixture keys)', async () => {
	const sealed = await encrypt('from the library', fixture.publicKey);
	assert.equal(await decrypt(sealed, fixture.privateKey), 'from the library');
	// The base64 form qrypt.chat's database returns opens too.
	assert.equal(await decrypt(toBase64(new TextEncoder().encode(sealed)), fixture.privateKey), 'from the library');
});

test('refuses the wrong key and a tampered envelope', async () => {
	const a = await generateKeyPair();
	const b = await generateKeyPair();
	const sealed = await encrypt('for a', a.publicKey);
	await assert.rejects(decrypt(sealed, b.privateKey), /wrong key or a damaged envelope/);

	const env = JSON.parse(sealed);
	const c = fromBase64(env.c);
	c[0] ^= 1;
	await assert.rejects(decrypt({ ...env, c: toBase64(c) }, a.privateKey), /wrong key or a damaged envelope/);
});

test('ML-KEM-768 still opens (qrypt.chat legacy messages)', async () => {
	const pair = await generateKeyPair({ algorithm: 'ML-KEM-768' });
	const sealed = await encrypt('old message', pair.publicKey, { algorithm: 'ML-KEM-768' });
	assert.equal(JSON.parse(sealed).alg, 'ML-KEM-768');
	assert.equal(await decrypt(sealed, pair.privateKey), 'old message');
});

test('more algorithms plug in, and envelopes pick theirs by alg', async () => {
	const xor = {
		name: 'TEST-XOR',
		async generateKeyPair() {
			return { publicKey: new Uint8Array([7]), privateKey: new Uint8Array([7]) };
		},
		async encrypt(plaintext, key) {
			return { v: 1, alg: 'TEST-XOR', c: toBase64(plaintext.map((x) => x ^ key[0])) };
		},
		async decrypt(env, key) {
			return fromBase64(env.c).map((x) => x ^ key[0]);
		},
	};
	registerAlgorithm(xor);
	const pair = await generateKeyPair({ algorithm: 'TEST-XOR' });
	const sealed = await encrypt('plug', pair.publicKey, { algorithm: 'TEST-XOR' });
	assert.equal(await decrypt(sealed, pair.privateKey), 'plug');
	assert.throws(() => registerAlgorithm({ name: 'broken' }), /needs name/);
	await assert.rejects(encrypt('x', pair.publicKey, { algorithm: 'NOPE' }), /Unknown algorithm/);
});

test('parseEnvelope rejects things that are not envelopes', () => {
	assert.throws(() => parseEnvelope('hello'), /Not an encrypted envelope/);
	assert.throws(() => parseEnvelope('{"no":"alg"}'), /Not an encrypted envelope/);
});

test('keys are the raw ML-KEM bytes qrypt.chat stores', async () => {
	const [pk, sk] = await new MlKem1024().generateKeyPair();
	const sealed = await encrypt('raw', pk);
	assert.equal(await decrypt(sealed, sk), 'raw');
	assert.equal(await decrypt(sealed, toBase64(sk)), 'raw');
});
