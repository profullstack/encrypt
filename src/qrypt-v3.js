/**
 * qrypt.chat's message encryption ("v3"), byte for byte:
 *
 *   1. ML-KEM (FIPS 203) encapsulation to the recipient's public key gives a
 *      KEM ciphertext and a 32-byte shared secret.
 *   2. HKDF-SHA-256(shared secret, 32-byte random salt,
 *      info "QryptChat-v1-ChaCha20-Poly1305") -> 32-byte key.
 *   3. ChaCha20-Poly1305 with a random 12-byte nonce seals the plaintext
 *      (the 16-byte tag is appended to the ciphertext).
 *
 * The envelope is JSON: { v: 3, alg, kem, s, n, c, t } with every byte field
 * standard base64 and t a millisecond timestamp. Envelopes made here open in
 * qrypt.chat and the other way round.
 */

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { MlKem1024, MlKem768 } from 'mlkem';
import { fromBase64, randomBytes, toBase64, wipe } from './bytes.js';

const INFO = new TextEncoder().encode('QryptChat-v1-ChaCha20-Poly1305');
const SALT_SIZE = 32;
const NONCE_SIZE = 12;
const KEY_SIZE = 32;

/**
 * An algorithm for the registry, built on one ML-KEM parameter set.
 * @param {string} name   the envelope's `alg`
 * @param {() => { generateKeyPair(): Promise<[Uint8Array, Uint8Array]>, encap(pk: Uint8Array): Promise<[Uint8Array, Uint8Array]>, decap(ct: Uint8Array, sk: Uint8Array): Promise<Uint8Array> }} kem
 */
function mlkemChaCha(name, kem) {
	return {
		name,
		async generateKeyPair() {
			const [publicKey, privateKey] = await kem().generateKeyPair();
			return { publicKey, privateKey };
		},
		/**
		 * @param {Uint8Array} plaintext
		 * @param {Uint8Array} publicKey
		 */
		async encrypt(plaintext, publicKey) {
			const [kemCiphertext, sharedSecret] = await kem().encap(publicKey);
			const salt = randomBytes(SALT_SIZE);
			const key = hkdf(sha256, sharedSecret, salt, INFO, KEY_SIZE);
			const nonce = randomBytes(NONCE_SIZE);
			const ciphertext = chacha20poly1305(key, nonce).encrypt(plaintext);
			wipe(key, sharedSecret);
			return { v: 3, alg: name, kem: toBase64(kemCiphertext), s: toBase64(salt), n: toBase64(nonce), c: toBase64(ciphertext), t: Date.now() };
		},
		/**
		 * @param {{ kem: string, s: string, n: string, c: string }} envelope
		 * @param {Uint8Array} privateKey
		 */
		async decrypt(envelope, privateKey) {
			const sharedSecret = await kem().decap(fromBase64(envelope.kem), privateKey);
			const key = hkdf(sha256, sharedSecret, fromBase64(envelope.s), INFO, KEY_SIZE);
			try {
				return chacha20poly1305(key, fromBase64(envelope.n)).decrypt(fromBase64(envelope.c));
			} finally {
				wipe(key, sharedSecret);
			}
		},
	};
}

export const ML_KEM_1024 = mlkemChaCha('ML-KEM-1024', () => new MlKem1024());
/** qrypt.chat's legacy parameter set; decrypts old messages, not a default. */
export const ML_KEM_768 = mlkemChaCha('ML-KEM-768', () => new MlKem768());
