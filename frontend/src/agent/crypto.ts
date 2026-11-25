// Deterministic cryptographic core. No network, no randomness except where noted.
import { p256 } from "@noble/curves/nist.js";
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const subtle = () => globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (s: string) => encoder.encode(s);
export const fromUtf8 = (b: Uint8Array) => decoder.decode(b);

export function b64url(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64url(s: string): Uint8Array {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const hex = (b: Uint8Array | ArrayBuffer) =>
  Array.from(b instanceof Uint8Array ? b : new Uint8Array(b))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

export function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Canonical JSON: recursively sorted keys, no whitespace (matches Python json.dumps(sort_keys, separators)).
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(o[k])).join(",") + "}";
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest("SHA-256", data as BufferSource));
}
export const sha256Hex = async (data: Uint8Array) => hex(await sha256(data));

// ---------------------------------------------------------------- BIP-39
export const normalizeMnemonic = (m: string) => m.trim().toLowerCase().split(/\s+/).join(" ");
export const newMnemonic = () => generateMnemonic(wordlist, 256); // 256-bit entropy -> 24 words
export const isValidMnemonic = (m: string) => validateMnemonic(normalizeMnemonic(m), wordlist);
export const wordCount = (m: string) => (m.trim() ? normalizeMnemonic(m).split(" ").length : 0);

const SALT = utf8("credential-agent/v1");

/** BIP-39 seed (PBKDF2-HMAC-SHA512, 2048) -> HKDF-SHA256 master root key, wrapped as non-extractable. */
export async function deriveMasterKey(mnemonic: string, passphrase: string): Promise<CryptoKey> {
  const seed = await mnemonicToSeed(normalizeMnemonic(mnemonic), passphrase);
  const ikm = await subtle().importKey("raw", seed as BufferSource, "HKDF", false, ["deriveBits"]);
  const root = new Uint8Array(
    await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: utf8("master-root-key") }, ikm, 256),
  );
  seed.fill(0);
  const master = await subtle().importKey("raw", root as BufferSource, "HKDF", false, ["deriveBits"]);
  root.fill(0); // zeroize raw root secret
  return master;
}

export async function seedHex(mnemonic: string, passphrase: string) {
  const s = await mnemonicToSeed(normalizeMnemonic(mnemonic), passphrase);
  const h = hex(s);
  s.fill(0);
  return h;
}

async function childBits(master: CryptoKey, info: string, bits: number): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle().deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: utf8(info) }, master, bits),
  );
}

export async function deriveIdHex(master: CryptoKey, label: string) {
  const b = await childBits(master, label, 128);
  const h = hex(b);
  b.fill(0);
  return h;
}

export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

/** HKDF(master, label) -> P-256 scalar -> non-extractable ECDSA signing key. */
export async function deriveSigningKey(master: CryptoKey, label: string): Promise<{ privateKey: CryptoKey; publicJwk: PublicJwk }> {
  const seed = await childBits(master, label, 384);
  const sk = p256.utils.randomSecretKey(seed);
  const pub = p256.getPublicKey(sk, false);
  const publicJwk: PublicJwk = { kty: "EC", crv: "P-256", x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33, 65)) };
  const jwk: JsonWebKey = { ...publicJwk, d: b64url(sk), ext: false };
  const privateKey = await subtle().importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  sk.fill(0);
  seed.fill(0);
  jwk.d = "";
  return { privateKey, publicJwk };
}

export async function deriveAesKey(master: CryptoKey, label: string): Promise<CryptoKey> {
  const raw = await childBits(master, label, 256);
  const k = await subtle().importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  raw.fill(0);
  return k;
}

export async function signBytes(key: CryptoKey, data: Uint8Array): Promise<string> {
  return b64url(await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, key, data as BufferSource));
}

export async function verifyBytes(jwk: PublicJwk, sigB64: string, data: Uint8Array): Promise<boolean> {
  const pub = await subtle().importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return subtle().verify({ name: "ECDSA", hash: "SHA-256" }, pub, fromB64url(sigB64) as BufferSource, data as BufferSource);
}

export type Sealed = { iv: string; ct: string };

export async function seal(key: CryptoKey, plaintext: Uint8Array, aad: string): Promise<Sealed> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle().encrypt({ name: "AES-GCM", iv, additionalData: utf8(aad) }, key, plaintext as BufferSource);
  return { iv: b64url(iv), ct: b64url(ct) };
}

export async function open(key: CryptoKey, sealed: Sealed, aad: string): Promise<Uint8Array> {
  const pt = await subtle().decrypt(
    { name: "AES-GCM", iv: fromB64url(sealed.iv) as BufferSource, additionalData: utf8(aad) },
    key,
    fromB64url(sealed.ct) as BufferSource,
  );
  return new Uint8Array(pt);
}

const CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}<>?~";

/** 64-char password from CSPRNG (rejection sampling, no modulo bias). Returned as bytes so it can be zeroized. */
export function randomPassword(len = 64): Uint8Array {
  const out = new Uint8Array(len);
  const limit = 256 - (256 % CHARSET.length);
  let i = 0;
  while (i < len) {
    const buf = globalThis.crypto.getRandomValues(new Uint8Array(len * 2));
    for (let j = 0; j < buf.length && i < len; j++) if (buf[j] < limit) out[i++] = CHARSET.charCodeAt(buf[j] % CHARSET.length);
    buf.fill(0);
  }
  return out;
}

export const PBKDF2_ITERATIONS = 100000;

/** Server-side verifier for a password: pbkdf2-sha256$iter$hex. */
export async function passwordVerifier(password: Uint8Array, domain: string): Promise<string> {
  const k = await subtle().importKey("raw", password as BufferSource, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: utf8("credential-agent:" + domain), iterations: PBKDF2_ITERATIONS },
    k,
    256,
  );
  return `pbkdf2-sha256$${PBKDF2_ITERATIONS}$${hex(bits)}`;
}

export const verifierFingerprint = (v: string) => v.split("$")[2].slice(0, 12);

export async function hmacHex(keyBytes: Uint8Array, msg: string): Promise<string> {
  const k = await subtle().importKey("raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await subtle().sign("HMAC", k, utf8(msg)));
}

/** HMAC-SHA256 challenge-response proof that we hold the candidate password. */
export async function passwordProof(password: Uint8Array, domain: string, rotationId: string, phase: string, ts: number) {
  const v = await passwordVerifier(password, domain);
  return hmacHex(fromHex(v.split("$")[2]), `${domain}|${rotationId}|${phase}|${ts}`);
}
