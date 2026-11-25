// Tier 2 hardware user verification via WebAuthn platform authenticator (Windows Hello / TPM on Windows,
// Touch ID on Mac, fingerprint/face on phones). The challenge is the transaction payload SHA-256.
import { b64url, fromB64url, fromHex } from "./crypto";

const g = globalThis as any;

export const webauthnSupported = () => typeof window !== "undefined" && !!g.PublicKeyCredential && !!g.navigator?.credentials;

export async function platformAuthenticatorAvailable(): Promise<boolean> {
  if (!webauthnSupported()) return false;
  try {
    return await g.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export type Tier2Credential = { credentialId: string; spki: string; alg: number; rpId: string };
export type Assertion =
  | { credentialId: string; authenticatorData: string; clientDataJSON: string; signature: string }
  | { simulated: true };

function friendly(e: any): Error {
  const name = e?.name ?? "";
  if (name === "NotAllowedError") return new Error("Windows Hello was cancelled or timed out");
  if (name === "SecurityError") return new Error("Biometrics blocked here - open the app in its own browser tab");
  return new Error(e?.message ?? String(e));
}

export async function createTier2Credential(agentId: string): Promise<Tier2Credential> {
  const rpId = window.location.hostname;
  try {
    const cred = await g.navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: "Aegis Credential Agent" },
        user: { id: fromHex(agentId), name: `agent-${agentId.slice(0, 8)}`, displayName: "Credential Agent Tier 2 key" },
        challenge: g.crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required", residentKey: "discouraged" },
        timeout: 60000,
        attestation: "none",
      },
    });
    const resp = cred.response;
    const spki = resp.getPublicKey?.();
    if (!spki) throw new Error("This browser cannot export the credential public key");
    return { credentialId: b64url(cred.rawId), spki: b64url(spki), alg: resp.getPublicKeyAlgorithm(), rpId };
  } catch (e) {
    throw friendly(e);
  }
}

export async function getTier2Assertion(credentialId: string, payloadSha256Hex: string): Promise<Assertion> {
  try {
    const a = await g.navigator.credentials.get({
      publicKey: {
        challenge: fromHex(payloadSha256Hex),
        rpId: window.location.hostname,
        allowCredentials: [{ type: "public-key", id: fromB64url(credentialId) }],
        userVerification: "required",
        timeout: 60000,
      },
    });
    const r = a.response;
    return {
      credentialId: b64url(a.rawId),
      authenticatorData: b64url(r.authenticatorData),
      clientDataJSON: b64url(r.clientDataJSON),
      signature: b64url(r.signature),
    };
  } catch (e) {
    throw friendly(e);
  }
}
