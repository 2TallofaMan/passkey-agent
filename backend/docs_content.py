"""Patent presentation documents (served in-app and as PDFs). Draft material to brief a patent attorney."""

DISCLOSURE = r"""# Invention Disclosure — Passtate
## Agent-held keystore and agent-owned passkeys for autonomous, verification-gated credential lifecycle management

**Status:** confidential draft for attorney review. Not a filing, not legal advice.

## 1. Field
Credential management, specifically autonomous rotation, propagation, verification and recovery of passwords, API access keys and passkeys under a zero-trust model, as a component that plugs into existing password managers.

## 2. Problem
- Automated password changers built on browser form-filling are brittle. Dashlane discontinued its automatic Password Changer in 2022; the approach depended on scripted interaction with each website's UI, which breaks whenever the UI changes.
- An "OK" page or HTTP 200 is not proof that a credential was changed. Prior tools assumed success, which can lock users out.
- A process crash, network loss or service outage mid-change leaves the vault and the service disagreeing on the current credential (desync).
- Fully autonomous agents are a security risk: if an agent can change credentials silently, an attacker who controls the agent can too.
- Passkeys remove passwords for interactive login but require the user to be present, so they do not on their own enable unattended maintenance.

## 3. Summary of the invention (central idea)
Passtate is a credential agent with **its own internal keystore** and **its own passkey (agent key pair) per service account**, deterministically derived from a user-held 24-word root secret and kept separate from the operating system's passkey manager. With these agent-owned credentials the agent can **prove its identity to a service cryptographically and act for the user without the user being present and without form-filling**. Every change is held in a **candidate slot** and only becomes the **current verified credential** after the service confirms it; the agent then **propagates** the new credential to dependents, confirms each one, and only then deletes the previous credential. A deterministic **policy engine** chooses one of three operating modes per account and per operation, and high-risk operations require a **hardware user-verification signature bound to the SHA-256 of the exact transaction payload**.

## 4. The eight-stage workflow
1. **Enroll** — create a credential record (service, account, credential type, encrypted material, state, policy/mode, next action, verification and recovery requirements). The agent generates its own per-account key pair `HKDF(master, "domain:" + service)` and registers the public key with the service.
2. **Policy** — the account inherits or overrides a management mode (Fully Automated, Approval Required, Reminder Only) at default, account and operation-type scope.
3. **Trigger** — schedule/credential age, exposure event (k-anonymous breach lookup), service notice (suspicious login / reset attempt), or user request.
4. **Decide** — a deterministic policy engine maps (credential, operation, trigger, mode, connector health, failure history) to a decision: allowed?, mode, connector, verification required, recovery path. Same inputs → same decision; the decision is displayed and logged.
5. **Execute via connector** — the agent signs each request with its own per-service key (canonical JSON, P-256), using a protocol connector (demo-service connector: password + agent passkey; AWS connector: create key / confirm / propagate / delete old). No UI scraping.
6. **Verify (gating)** — the candidate credential is proven before commit: challenge-response proof, a real sign-in with the candidate, or (AWS) an identity call made with the new key. An attempted change is not a verified change.
7. **Propagate** — push the verified credential to every dependent (paired-device sessions preserved; dependent applications switched) and confirm each target is healthy on the new credential before purging the old one. Unknown sessions are revoked.
8. **Recover** — on restart/reconnect, any record left STAGED or VERIFYING is resolved by testing both slots against the live service, keeping whichever works, deleting the dead one, and resuming or rolling back. Total device loss is recovered from the 24-word phrase plus a zero-knowledge encrypted backup.

## 5. How each part solves a zero-trust problem
| Component | Zero-trust problem solved |
|---|---|
| Agent-owned keystore & per-service agent passkeys | Agent can authenticate unattended without impersonating the user or reusing the user's personal passkeys |
| Dual-slot (current / candidate) state | No single write can destroy the only working credential |
| Verification gating | Success is never assumed; service confirmation is required evidence |
| Ordered propagation then purge | Dependents never lose access; old credential retained as fallback until all targets confirm |
| Deterministic policy engine | Behaviour is auditable and reproducible; no natural-language or model-driven decisions |
| Tiered approvals bound to payload hash | A compromised agent cannot obtain approval for a different action than the one displayed |
| Replay-protected signed wire protocol | Captured requests cannot be re-sent |
| Crash-safe recovery by slot probing | Process death, network loss or outage never causes permanent desync |
| Seed-derived determinism + encrypted backup | Replacement device rebuilds every agent key and restores live credentials |

## 6. What is believed to be new (for attorney evaluation)
- An autonomous credential agent holding a **separate agent keystore with per-account agent key pairs registered with services**, used as the agent's own authenticator for credential-lifecycle operations, distinct from the user's passkeys.
- **Verification-gated dual-slot commit** in which the candidate is promoted only after service-side proof, and the prior credential is purged only after **all propagation targets confirm** use of the candidate.
- **Boot-time reconciliation** that probes both slots against the live service and deterministically keeps the working slot.
- **Per-account, per-operation policy scopes** selecting among Fully Automated, Approval Required and Reminder Only, with automatic escalation to a more restrictive mode after repeated failure.
- **Transaction-bound hardware approval**: the WebAuthn/biometric challenge is the SHA-256 of the canonical payload shown to the user.
- **Session-preserving rotation**: rotation request carries the list of trusted device sessions to keep while revoking unknown sessions.
- Deterministic derivation of every agent key from a BIP-39 root so that agent credentials are recoverable without the service's involvement.

## 7. Reference implementation (demo)
Web agent (WebCrypto non-extractable keys, IndexedDB, AES-256-GCM vault), WebAuthn platform authenticator (Windows Hello) for Tier 2, hosted demo services with real login/sessions/password change, and a real AWS IAM access-key connector that uses AWS's two-key limit as the current/candidate slots, plus a dependent application that calls AWS continuously to demonstrate zero-downtime propagation.
"""

DIAGRAMS = r"""# Passtate — Workflow Diagrams

## 1. End-to-end flow
```
 Trigger (schedule | exposure | service notice | user)
        |
        v
 +----------------+     deny/remind     +------------------+
 | Policy engine  |-------------------->| Reminder / Audit |
 | (deterministic)|                     +------------------+
 +----------------+
        | allowed (mode = AUTO | APPROVAL)
        v
 [APPROVAL?] --yes--> Tier 2: hardware UV over SHA-256(payload)
        |
        v
 Connector (agent-signed, no form-filling)
        |
        v
 Candidate slot staged --> Service confirms --> Verified
        |                                         |
        | fail                                    v
        v                               Propagate to dependents
 Recovery path                          (confirm each target)
 (retry | other connector |                       |
  escalate mode | ask user)                       v
                                       Purge previous credential
```

## 2. Slot state transitions
```
           stage (local commit)        remote accept
  IDLE ---------------------> STAGED ---------------> VERIFYING
   ^                            |                        |
   |  probe: active works       | crash/offline          | service proof OK
   |  (wipe candidate)          v                        v
   +----------------------- RECOVERY <------------- COMMITTED (candidate -> current)
   |                            |                        |
   |  probe: candidate works    |                        | all targets confirmed
   +----(promote candidate)-----+                        v
   +------------------------------------------------ PURGE old -> IDLE
                     neither slot works -> DESYNC (ask user)
```

## 3. Operating modes
```
 FULLY AUTOMATED : trigger -> decide -> execute -> verify -> propagate -> commit
 APPROVAL REQUIRED: trigger -> decide -> prepare -> [user hardware UV] -> execute -> verify -> commit
 REMINDER ONLY   : trigger -> decide -> remind user -> user changes -> agent independently confirms
```

## 4. Recovery paths
```
 failure type            first response           after repeated failure
 ---------------------   ----------------------   --------------------------
 crash mid-rotation      probe both slots         keep working slot, resume
 network offline         keep state, wait online  resume on reconnect
 service outage (5xx)    retry next tick          escalate to APPROVAL_REQUIRED
 proof rejected (409)    probe active slot        keep active, wipe candidate
 AWS 2-key limit         list keys, delete dead   resume rotation
 neither slot verifies   DESYNC                   ask user (Reminder Only)
```
"""

PRIOR_ART = r"""# Prior Art Comparison — Passtate

**Note:** summaries are for orientation only; the attorney should review the full texts.

| Reference | What it does | What it lacks compared with Passtate |
|---|---|---|
| Dashlane Password Changer (discontinued 2022) | Automated password changes by scripting each website's change-password UI | Depends on form-filling, breaks on UI change; no agent-owned keys; no service-side verification gating; no dual-slot crash recovery |
| W3C "A Well-Known URL for Changing Passwords" (`/.well-known/change-password`) | Standard redirect telling a password manager where a site's change-password page is | Only locates the page; the change is still manual or form-filled; no protocol for agent authentication, verification or rollback |
| US 10,169,569 (Okta) "Automated password generation and change" | Identity system uses learned heuristics to interact with third-party login pages and change passwords on triggers; propagates to devices via device management | Heuristic UI interaction (form-filling class); no agent-owned per-service key pairs; no verification-gated dual-slot commit or slot-probing recovery; no transaction-bound hardware approvals |
| US 9,824,208 (Unisys) "Cloud-based active password manager" | Server generates new passwords from a device seed and prior timestamp; auto-login; time-based updates | Seed-derived passwords rather than agent keys registered with services; no service confirmation before commit; no ordered propagation/purge; no tiered approvals |
| Passkeys (WebAuthn / FIDO2) | Phishing-resistant user authentication with device-bound key pairs | Designed for a present user; does not rotate fallback passwords or API keys; no lifecycle agent, policy engine or propagation |
| AWS IAM access-key rotation guidance | Manual/scripted create new key → update apps → deactivate → delete old (two-key limit) | Single-service procedure; no cross-service agent, policy modes, hardware approvals, crash reconciliation or seed-based recovery |

## Distinguishing combination
Agent-owned keystore and per-service agent passkeys **+** verification-gated dual-slot commit **+** confirmed propagation before purge **+** deterministic per-operation policy modes **+** payload-hash-bound hardware approvals **+** slot-probing crash recovery **+** seed-derived recoverability.
"""

PITCH = r"""# Passtate — One-Page Pitch for Password Manager Companies

## The problem you already know
Users never rotate credentials. Automatic password changers failed because they relied on form-filling bots (Dashlane retired its changer in 2022). Every failed change risks locking a customer out of their account.

## What Passtate is
A **credential agent** that plugs into your existing vault. It has **its own keystore and its own passkey for each service**, so it can prove who it is and act for the user without the user being present — and without touching website forms.

## Why it works where others failed
- **No form-filling:** the agent authenticates cryptographically through connectors.
- **Never assumes success:** a credential only counts after the service confirms it.
- **Crash-proof:** current and candidate slots; recovery tests both and keeps the working one.
- **Zero downtime:** new credentials are pushed to devices and apps and confirmed before the old one is deleted.
- **Zero trust:** routine work runs silently; high-risk actions need a fingerprint/face check bound to that exact request.
- **Recoverable:** a 24-word phrase rebuilds every agent key on a new device.

## What you get
- Differentiated feature: "credentials that maintain themselves", with an audit trail and live metrics.
- Works today on API keys (AWS demonstrated live) and on services that adopt the open agent protocol.
- Three policy modes your enterprise customers can enforce per account and per operation.

## How it plugs in
Your vault remains the system of record and UI. Passtate runs as an agent module beside it: it reads credential records, writes candidate/current slots, and reports decisions and evidence to your audit log.

## Ask
Pilot integration with one vault and one connector set, plus patent licensing discussion.
"""

INTEGRATION = r"""# Passtate Integration Guide

## For a password manager (vault)
1. **Credential record mapping** — add fields: credential type, current slot, candidate slot, rotation state (IDLE / STAGED / VERIFYING), mode, policy scope, next action, verification and recovery requirements.
2. **Agent keystore** — store agent key handles (non-extractable / hardware-backed) separately from user passkeys. Derive per-account agent keys from the vault's root secret: `HKDF(master, "domain:" + service)`.
3. **Durable state writes** — commit the candidate slot before any network call; never overwrite the current slot until verification.
4. **Policy engine hook** — expose default / per-account / per-operation modes to admins.
5. **Approval surface** — render the approval sheet (action, service, device/IP, time, payload SHA-256) and call the platform authenticator with the payload hash as the challenge.
6. **Recovery on start** — scan for STAGED / VERIFYING records and run slot probing.
7. **Audit** — log decisions and verification evidence; never log credential material.

## For a service (relying party)
Expose signed JSON endpoints under `/.well-known/credential-agent/`:
- `enroll` — register the agent's public key for an account.
- `rotate-stage` — accept the candidate credential hash and the list of sessions to preserve.
- `rotate-verify` — `VERIFY_AND_COMMIT` (proof of candidate), `PROBE` (which slot is valid), `ACK_PURGE` (delete previous).
- `recovery-challenge` — let the agent reject unauthorized reset attempts.
- `step-up` — verify a hardware user-verification assertion bound to the payload hash.
Requirements: verify `X-Agent-Signature` over canonical JSON, reject replays and stale timestamps, sign responses (`X-RP-Signature`), keep the previous credential until `ACK_PURGE`.

## Services that cannot adopt the protocol
Use provider APIs that already have two-slot credentials (AWS IAM access keys, Cloudflare API tokens, GitHub deploy keys) through connectors, or run the account in Reminder Only mode with independent confirmation.
"""

DOCS = {
    "invention-disclosure": ("Invention Disclosure", DISCLOSURE),
    "workflow-diagrams": ("Workflow Diagrams", DIAGRAMS),
    "prior-art": ("Prior Art Comparison", PRIOR_ART),
    "pitch-summary": ("One-Page Pitch Summary", PITCH),
    "integration-guide": ("Integration Guide", INTEGRATION),
}
