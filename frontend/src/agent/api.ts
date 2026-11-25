// Signed wire transport. Requests: canonical JSON + X-Agent-Signature. Responses: verified X-RP-Signature (pinned RP key).
import { canonicalJson, PublicJwk, signBytes, utf8, verifyBytes } from "./crypto";
import { idbGet, idbPut } from "./idb";

const BASE = `${process.env.EXPO_PUBLIC_BACKEND_URL}/api`;
export const WK = "/.well-known/credential-agent";

export class RpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(`${code}: ${message}`);
    this.status = status;
    this.code = code;
  }
}

let rpKey: (PublicJwk & { allowSimulatedUV?: boolean }) | null = null;

export async function getRpKey() {
  if (rpKey) return rpKey;
  const r = await fetch(`${BASE}${WK}/rp-key`);
  const live = await r.json();
  const jwk: PublicJwk = { kty: "EC", crv: "P-256", x: live.x, y: live.y };
  const pinned = await idbGet<PublicJwk>("meta", "rpKey");
  if (pinned && (pinned.x !== jwk.x || pinned.y !== jwk.y)) throw new Error("RP signing key changed - pinned key mismatch");
  if (!pinned) await idbPut("meta", "rpKey", jwk);
  rpKey = { ...jwk, allowSimulatedUV: !!live.allowSimulatedUV };
  return rpKey;
}

export const resetRpKeyCache = () => {
  rpKey = null;
};

async function handle(r: Response) {
  const text = await r.text();
  const sig = r.headers.get("X-RP-Signature");
  if (!sig) throw new RpError(r.status, "UNSIGNED_RESPONSE", text.slice(0, 120));
  const key = await getRpKey();
  if (!(await verifyBytes(key, sig, utf8(text)))) throw new RpError(r.status, "BAD_RP_SIGNATURE", "RP response signature invalid");
  const data = JSON.parse(text);
  if (!r.ok) throw new RpError(r.status, data.error ?? "ERROR", data.message ?? "Request failed");
  return data;
}

export async function signedSend(method: "POST" | "PUT", path: string, body: object, agentId: string, key: CryptoKey) {
  const text = canonicalJson(body);
  const sig = await signBytes(key, utf8(text));
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-Agent-Id": agentId, "X-Agent-Signature": sig },
    body: text,
  });
  return handle(r);
}

export async function signedGet(path: string) {
  return handle(await fetch(`${BASE}${path}`));
}

export async function plain(method: "GET" | "POST", path: string, body?: object) {
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : {};
  if (!r.ok) throw new RpError(r.status, data.error ?? "ERROR", data.message ?? data.detail ?? "Request failed");
  return data;
}
