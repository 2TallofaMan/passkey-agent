// Have I Been Pwned k-anonymity range check: only the first 5 hex chars of SHA-1 leave the device.
import { hex } from "./crypto";

export async function pwnedCount(password: Uint8Array): Promise<{ count: number; prefix: string }> {
  const h = hex(await globalThis.crypto.subtle.digest("SHA-1", password as BufferSource)).toUpperCase();
  const prefix = h.slice(0, 5);
  const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } });
  if (!r.ok) throw new Error(`Breach service returned ${r.status}`);
  const text = await r.text();
  const line = text.split("\n").find((l) => l.startsWith(h.slice(5)));
  return { count: line ? parseInt(line.split(":")[1], 10) : 0, prefix };
}
