/** An algorithm in the registry. Byte arrays in and out; the library handles base64. */
export interface Algorithm {
  /** The envelope's `alg`. */
  name: string;
  generateKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  encrypt(plaintext: Uint8Array, publicKey: Uint8Array): Promise<Envelope>;
  decrypt(envelope: Envelope, privateKey: Uint8Array): Promise<Uint8Array>;
}

/** qrypt.chat's v3 envelope; other algorithms may add fields. */
export interface Envelope {
  v: number;
  alg: string;
  kem?: string;
  s?: string;
  n?: string;
  c?: string;
  t?: number;
  [field: string]: unknown;
}

export interface KeyPair {
  algorithm: string;
  /** base64 */
  publicKey: string;
  /** base64 */
  privateKey: string;
}

export const DEFAULT_ALGORITHM: "ML-KEM-1024";
export function algorithms(): string[];
export function registerAlgorithm(algorithm: Algorithm): void;
export function generateKeyPair(options?: { algorithm?: string }): Promise<KeyPair>;
export function encrypt(data: string | Uint8Array, publicKey: string | Uint8Array, options?: { algorithm?: string }): Promise<string>;
export function parseEnvelope(input: string | Envelope): Envelope;
export function decrypt(envelope: string | Envelope, privateKey: string | Uint8Array, options?: { encoding?: "utf8" }): Promise<string>;
export function decrypt(envelope: string | Envelope, privateKey: string | Uint8Array, options: { encoding: "bytes" }): Promise<Uint8Array>;
