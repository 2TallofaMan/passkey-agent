# Passtate: Zero-Trust Auto-Rotation Demo and Patent Presentation Kit

Passtate is a credential agent with its own keystore and its own passkeys. It acts for the user to rotate, propagate, verify and recover credentials on real services. It is built to plug into any existing password manager, not to be sold as one.
This build is a working live demo using real credentials on real services, plus downloadable patent presentation documents. It is not an app for public release.

## Who it's for
- **Presenter (you):** runs the demo live in meetings with password manager companies, then lets anyone in the room try it.
- **Audience:** product, security and partnership leads. They need to see the system solve the problems that made earlier attempts fail, in real time.
- **Patent attorney:** receives the disclosure documents.

## The central idea the demo and documents are built around
- **The agent's own credentials:** the agent has its own internal keystore and its own passkey for each service, separate from the device's built-in passkey manager. With these, it can prove who it is and act for the user without the user being present, and without anyone typing or clicking through website forms.
- **Why earlier attempts failed:** Dashlane's automatic password changer was discontinued in 2022 because form-filling bots kept breaking. Passtate does not depend on form-filling. The agent proves itself cryptographically, and every change is confirmed by the service before it counts.
- **Everything else:** dual-slot state, verification gating, tiered approvals, crash recovery and propagation exist to solve the problems that come with letting an agent act alone in a zero-trust system.

## Core features and experience

### 1. Enroll a service or account
- **Credential record:** each record holds:
  - Service and account identity
  - Credential type (password, API access key, passkey)
  - Encrypted credential material
  - Current state
  - Management policy and operating mode
  - Next scheduled action
  - Verification and recovery requirements
- **Agent passkey at enrollment:** the agent creates its own passkey for that account and registers it with the service.
- **Separate from the device:** the agent never takes over the operating system's passkey manager.
- **Two kinds of services can be enrolled:**
  - **Real demo services:** separate, running websites with real login, sessions and password change. They use standard passkey checks, not scripted responses.
  - **One real outside connection: Amazon Web Services (AWS) access keys.** The agent rotates the real keys on your AWS account (a dedicated test user). AWS allows exactly two keys per user, which mirrors the current/candidate slot design.

### 2. Management policy per account
- **Fully Automated:** the agent performs the change through its connector, verifies it and commits it.
- **Approval Required:** the agent prepares the change. The user approves with a fingerprint or face check tied to that exact request, then the agent completes, verifies and commits it.
- **Reminder Only:** the agent reminds the user. The user changes the credential themselves, and Passtate can independently confirm the change.
- **Policy scope:** policy can be set per account, per operation type (rotation, new device, backup export, ownership change), or as a default.

### 3. Triggers (all real)
- **Schedule:** a rotation date or a credential age. The demo default is every 30 minutes, plus "Rotate now".
- **Exposure event:** a real breach check against the public Have I Been Pwned password database. Only a short hash prefix leaves the device, never the password.
- **Service notice:** a demo service reports a suspicious login or a password-reset attempt.
- **User request:** the user asks for a change.

### 4. Policy engine
- **What it decides:** which credential, which operation, whether it is allowed, which mode applies, which connector to use, what verification is needed, and what recovery applies if it fails.
- **Deterministic:** the same inputs always give the same decision.
- **Shown live:** the engine's decision appears on screen as a "decision card" each time.

### 5. Agent execution through connectors
- **Connectors:**
  - Demo-service connector: password plus agent passkey.
  - AWS connector: create the new access key, confirm it with AWS, propagate it, then delete the old key.
- **Agent signing:** the agent signs every request with its own key for that service.
- **No assumed success:** a clicked button or an "OK" response alone is never taken as success.

### 6. Verification-gated credential state
- **Slots:** each credential has a current verified slot and a candidate slot.
- **Operation states:** pending, verified, failed or unverified.
- **Previous credential:** the old credential is kept as a fallback until the change is verified and acknowledged.
- **What counts as verification:**
  - A real sign-in with the candidate credential.
  - A challenge-response proof.
  - For AWS, a real "who am I" call made with the new key.
- **Rule:** an attempted change is not a verified change. Nothing replaces the current verified state until the service confirms it.

### 7. Auto propagation
- **What it does:** once a new credential is verified, the agent pushes it to every place that depends on it, and checks each one.
- **Where it pushes:**
  - Paired devices stay signed in: their sessions are carried through the rotation.
  - A demo "dependent app" switches to the new AWS key without breaking. It calls AWS continuously and shows a live "still working" indicator.
- **Ordering:** the old credential is deleted only after every place that uses it has been confirmed on the new one.
- **Unknown sessions:** sessions from unknown devices are signed out during the rotation.

### 8. Failure, recovery and fallback (crash-proof, shown for real)
- **Slow-motion mode:** pauses between each phase, so the presenter can really break things:
  - close the browser tab or kill the app mid-rotation
  - turn off Wi-Fi
  - take a demo service offline with one switch
- **Recovery on reopen or reconnect:** the agent:
  1. tests both slots against the real service
  2. keeps whichever works
  3. deletes the dead one
  4. resumes or rolls back
- **Recovery options:** retry, switch to another connector, raise the mode to Approval Required or Reminder Only, or ask the user to step in.
- **Chaos lab stays:** the existing chaos lab remains for repeatable tests. The headline demo uses real interruptions.

### 9. Tiered approvals (zero trust)
- **Routine work runs silently:**
  - rotations
  - auto-rejecting password resets from unknown devices
  - signing out unknown sessions
- **High-risk work needs a fingerprint or face check bound to the exact request:**
  - pairing a new device
  - exporting a backup
  - changing the account owner
  - raising a credential's mode
- **Approval sheet:** shows the action, service, requesting device and IP, time, and a fingerprint (hash) of the request.

### 10. Recovery from total loss
- **24-word recovery phrase:** every agent key and passkey is rebuilt from it on a replacement device.
- **Encrypted backup:** live credentials are restored from a backup that only the user can decrypt.
- **Live demo:** wipe the device on stage, restore it, and the dependent app keeps working.

### 11. Audit and lifecycle tracking
- **Operation record fields:** credential ID, trigger, mode, connector, status, verification evidence, recovery action and next due date.
- **No secrets:** audit records never contain credential material.
- **Live metrics:** rotations, attacks blocked, sessions signed out, crashes recovered, recovery time and propagation targets confirmed.

### 12. Presenter mode and hand-off
- **Guided story:** a step-by-step walkthrough:
  1. Enroll with the agent's passkey.
  2. Silent rotation.
  3. Real crash, then recovery.
  4. Breach trigger.
  5. Blocked reset attack.
  6. Approval by fingerprint or face.
  7. AWS key rotation with zero downtime.
  8. Wipe and restore.
- **Step labels:** each step names the real-world problem it solves.
- **"Try it yourself":** one tap opens a fresh, separate sandbox for a guest. Your presenter data stays untouched.
- **Signed test report:** one tap produces a summary that shows if it has been tampered with, to hand out after the meeting.

### 13. Patent presentation documents (in the app and as downloadable PDFs)
- **Invention disclosure:** the full Passtate workflow in your 8 stages, with the agent's own keystore and passkeys as the central idea. It explains how each part solves a zero-trust problem and lists the "what's new" points.
- **Workflow diagrams:** the full flow, the slot state transitions, the three modes and the recovery paths.
- **Prior art comparison:**
  - Dashlane's discontinued changer
  - The browser standard for a "change password" link
  - Automatic-rotation patents US 10,169,569 and US 9,824,208
  - Passkeys and AWS's own rotation guidance
  - For each: what it lacks compared with Passtate
- **One-page pitch summary:** for password manager companies, covering how Passtate plugs into an existing vault.
- **Integration guide:** what a password manager adds and what a service adds.

## User flow
1. **Choose a mode:** the presenter opens Passtate on a laptop and picks presenter mode or free use.
2. **Run the guided story:** the presenter goes through it with real interruptions. A phone is used for fingerprint or face approvals.
3. **Live screens:** the metrics dashboard and the dependent app's "still working" indicator stay visible throughout.
4. **Hand-off:** at the end, the presenter creates the signed report, shows the patent documents, and hands guests a fresh sandbox to try.

## UI/UX feel
- **Look:** dark, high-contrast "security operations" style with orange accents, monospace hashes and clear status badges. The existing look stays.
- **Presenter mode:** large type, one idea per screen, a clear timeline of phases, and a pause indicator in slow-motion mode.
- **Phone:** a full-screen approval sheet with one large fingerprint or face button.

## Implementation phases

### Phase 1: MVP (built now)
- Rebrand to Passtate, with the credential record, the three modes and policy scopes
- Policy engine with on-screen decision cards
- Real demo services (separate running websites with real login, sessions and password change) with agent-owned passkeys
- One real outside connection: AWS access key rotation, verification and deletion of the old key
- Auto propagation to paired-device sessions and a live dependent app
- Real triggers: schedule, breach check, service notice, user request
- Slow-motion mode with real crash, offline and service-outage recovery
- Tiered approvals with phone and Windows Hello fingerprint or face checks
- Presenter story, guest sandbox and signed test report
- Hardening: replay blocking, recovery phrase removed from the page while hidden, simulated approvals off by default
- Patent documents, in the app and as PDFs

### Phase 2
- A second real connection type, for example Cloudflare API tokens or GitHub deploy keys
- Propagating rotated keys into GitHub repository secrets
- Approving a computer's request on a paired phone
- Installable phone builds with keys held in the phone's security chip
- Browser extension that fills in the current credential

### Phase 3
- Partner kit with a sample integration into one password manager's vault
- Formal open-standard specification
- Admin view for partners running pilots

## Assumptions
- **Name and branding:** the product name is Passtate.
- **"Zero day trust":** read as zero trust, meaning nothing is trusted by default and every action is verified.
- **Real connection: AWS access keys.** Normal websites offer no supported way to change a password automatically, while AWS does, safely, for free and with exactly two key slots.
  - It needs a dedicated test user on an AWS account you provide, with permission only to manage its own keys.
  - Your key is entered through a secure form, not in chat.
- **Real demo services:** they are genuine running websites, not simulations. They are hosted with the demo rather than being third-party websites.
- **Breach checks:** use the free public Have I Been Pwned password check. No account is needed.
- **Fingerprint/face check:**
  - On the laptop, Windows Hello is used, and its keys are held in the laptop's security chip.
  - On the phone, the preview app uses the phone's standard check. Chip-held keys on the phone come in Phase 2.
- **Passtate never touches the user's personal passkeys:**
  - The agent's service passkeys and keys live only in Passtate's own internal keystore.
  - The fingerprint or face check only confirms that the user is present for a high-risk approval. It uses a separate approval key that Passtate creates for itself; it never reads, uses or changes the passkeys the user keeps in Windows, Android or iOS.
  - Where a device has a security chip (Windows Hello on the laptop, and later the phone's chip), the chip is used only as a locked box for Passtate's own keys, walled off from everything else.
- **Patent documents:** prepared to brief a patent attorney. They are not a filing or legal advice.
- **Not for public release:** there is no app store release, payments or public sign-up. Guests use a temporary sandbox.
- **Rotation schedule:** the default stays at 30 minutes, with "Rotate now" for live demos.
