# Aegis — Deterministic Credential & Passkey Agent (Windows / Web edition)

Web app (Expo, runs in Edge/Chrome on Windows) + mock Relying Party (FastAPI). No LLM or free‑text parsing anywhere;
every message is canonical JSON signed with P‑256 keys (`X-Agent-Signature` / `X-RP-Signature`).

## Android → Windows/Web mapping
| Original (Android)                      | This build                                                                 |
|-----------------------------------------|----------------------------------------------------------------------------|
| Android Keystore / StrongBox            | Non-extractable WebCrypto keys in IndexedDB; TPM-backed Windows Hello key for Tier 2 |
| BiometricPrompt + CryptoObject          | WebAuthn platform authenticator (Windows Hello), challenge = payload SHA-256, UV flag verified server-side |
| Room + SQLCipher                        | IndexedDB records; password slots AES-256-GCM with a seed-derived vault key |
| WorkManager / BOOT_COMPLETED            | In-app scheduler (30 min interval, 15 s tick) + recovery scan on every app start / "Simulate reboot" |
| FLAG_SECURE                             | Seed blurred by default, hold-to-reveal, re-blurs on window blur / tab hide, not selectable |
| Ktor mock server                        | FastAPI `/api/.well-known/credential-agent/*`                              |

## Endpoints
`rotate-stage`, `rotate-verify` (`VERIFY_AND_COMMIT` | `PROBE` | `ACK_PURGE`), `recovery-challenge`, `step-up`,
plus `agent/register`, `tier2/register`, `enroll`, `PUT /api/backup`, `GET /api/backup/{id}` and test simulators under `/api/rp/simulate/*`.

## Testing Windows Hello (equivalent of `adb -e emu finger touch 1`)
1. Real device: Windows Settings → Accounts → Sign-in options → set up Fingerprint / Facial recognition (or PIN).
   Open the app **in its own browser tab** (WebAuthn is blocked inside preview iframes) → Settings → *Enroll Windows Hello*.
2. No biometric hardware: Chrome/Edge DevTools → ⋮ → More tools → **WebAuthn** → *Enable virtual authenticator environment* →
   add authenticator: protocol `ctap2`, transport `internal`, ✅ resident keys, ✅ **user verification**, ✅ "User verified" checked.
   Every Tier 2 approval is then auto-verified by the virtual authenticator.
3. Mock server test mode: `ALLOW_SIMULATED_UV="true"` in `backend/.env` enables a clearly labelled "simulated" approval
   button. Set it to `false` for production-like behaviour.

## Chaos tests
Chaos tab → pick a crash point → *Rotate & crash* → *Simulate reboot* → *Check sync*, or *Run full chaos suite* to
exercise all four crash points with an automatic PASS/FAIL per point. Settings → *Run self-tests* covers the BIP-39 reference
vector, deterministic key restoration, encrypted backup round-trip, signature checks and key non-extractability.
