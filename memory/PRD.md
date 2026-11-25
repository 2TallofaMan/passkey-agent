# PRD — Aegis Deterministic Credential & Passkey Agent (Windows/Web edition)

## Original problem
Android Kotlin deterministic credential agent + Ktor mock RP (BIP-39 seed, Keystore/StrongBox, dual-slot crash-safe rotation, BiometricPrompt Tier 2, Credential Provider, session broker). User redirected: build as a WEB app targeting Windows equivalents; real biometric check; rotate every 30 min; include chaos test panel.

## Architecture
- Frontend: Expo web (expo-router tabs: Vault, Chaos, Audit, Settings + Onboarding). Core in `src/agent/` (crypto.ts, idb.ts, api.ts, webauthn.ts, agent.ts).
- Keys: BIP-39 (@scure/bip39) → PBKDF2-HMAC-SHA512 seed → HKDF-SHA256 master (non-extractable WebCrypto) → per-domain P-256 (HKDF "domain:<d>"), vault AES key, backup AES key, agent identity key.
- Storage: IndexedDB, slots AES-256-GCM encrypted. Tier 2: WebAuthn platform authenticator (Windows Hello), challenge = payload SHA-256, verified server-side (UV flag + signature).
- Backend: FastAPI mock RP `/api/.well-known/credential-agent/*` (signed canonical JSON both directions), backup store, simulators. `ALLOW_SIMULATED_UV=true` enables test-only approvals.

## Implemented (2026-06)
- Onboarding (create/confirm/restore), blur-protected seed reveal
- 4-phase rotation (stage → remote update → verify → commit + ACK purge), 30-min scheduler, boot/reboot recovery, cross-tab Web Locks, ACK retry
- Chaos lab (4 crash points, reboot, sync check, full suite) + attack sims (untrusted reset auto-reject, pairing, ownership change, trusted reset)
- Tier 2 approval sheet, session preservation/revocation, zero-knowledge backup (Tier 2 export, Tier 1 auto-sync), audit ledger, self-tests, wipe & restore
- AGENT_README.md with Windows Hello / DevTools virtual authenticator testing

## Backlog
- P1: Replay protection (nonce/requestId store), seed words not in DOM while blurred
- P2: Split agent.ts, FastAPI lifespan migration, OAuth refresh-token renewal (Tier 1), browser notifications for Tier 2 requests
