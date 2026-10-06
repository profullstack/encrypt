# @profullstack/encrypt

Quantum-resistant encrypt and decrypt for JavaScript. The default is the scheme
[qrypt.chat](https://qrypt.chat) uses for every message:

- **ML-KEM-1024** (FIPS 203, formerly Kyber) to agree a key with the recipient's public key
- **HKDF-SHA-256** to turn that into a 32-byte key
- **ChaCha20-Poly1305** to encrypt and authenticate the data

Envelopes are wire-compatible with qrypt.chat in both directions, and keys are
the same base64 keys qrypt.chat stores. More algorithms plug in as they are needed.

Works in Node 20+, Bun, Deno and browsers. Pure JavaScript, three small audited
dependencies (`mlkem`, `@noble/ciphers`, `@noble/hashes`).

## Install

```sh
npm i @profullstack/encrypt
```

## Use it

```js
import { generateKeyPair, encrypt, decrypt } from '@profullstack/encrypt';

const { publicKey, privateKey } = await generateKeyPair(); // ML-KEM-1024, base64

const sealed = await encrypt('meet at 9', publicKey);        // JSON envelope string
const text = await decrypt(sealed, privateKey);              // 'meet at 9'

// bytes work too
const file = await decrypt(await encrypt(bytes, publicKey), privateKey, { encoding: 'bytes' });
```

`decrypt` throws on a wrong key or a tampered envelope; ChaCha20-Poly1305 authenticates every byte.

The envelope:

```json
{ "v": 3, "alg": "ML-KEM-1024", "kem": "<base64>", "s": "<salt>", "n": "<nonce>", "c": "<ciphertext+tag>", "t": 1791274226358 }
```

`decrypt` also accepts the base64 of that JSON (how qrypt.chat's API returns it) or a parsed object.

## Algorithms

| `alg` | Use |
| --- | --- |
| `ML-KEM-1024` | default, NIST level 5 |
| `ML-KEM-768` | qrypt.chat's legacy messages |

```js
import { algorithms, registerAlgorithm } from '@profullstack/encrypt';

algorithms(); // ['ML-KEM-1024', 'ML-KEM-768']

registerAlgorithm({
  name: 'MY-ALG',
  async generateKeyPair() { /* { publicKey, privateKey } as Uint8Array */ },
  async encrypt(plaintext, publicKey) { /* an envelope object with alg: 'MY-ALG' */ },
  async decrypt(envelope, privateKey) { /* Uint8Array */ },
});
await encrypt('x', key, { algorithm: 'MY-ALG' });
```

`decrypt` picks the algorithm from the envelope's `alg`, so old and new envelopes open side by side.

## CLI

```sh
npx @profullstack/encrypt keygen --out alice        # alice.pub, alice.key (0600)
pfencrypt encrypt --to alice.pub notes.txt > notes.enc
pfencrypt decrypt --key alice.key notes.enc
cat notes.enc | PFENCRYPT_KEY="$(cat alice.key)" pfencrypt decrypt
pfencrypt algorithms
```

## MCP

`pfencrypt mcp` is an MCP server on stdio with `encrypt`, `decrypt`,
`generate_keypair` and `list_algorithms`. Private keys never pass through the
model: `decrypt` reads the key from `PFENCRYPT_KEY` or a key file, and
`generate_keypair` writes the private key to disk and returns only the public key.

```json
{ "mcpServers": { "encrypt": { "command": "npx", "args": ["-y", "@profullstack/encrypt", "mcp"], "env": { "PFENCRYPT_KEY": "..." } } } }
```

## Security notes

- Each message uses a fresh KEM encapsulation, salt and nonce; nothing is reused.
- The derived key and shared secret are zeroed after use (best effort in JavaScript).
- This is encryption to a public key, not a signature: it says nothing about who sent a message.

## License

MIT
