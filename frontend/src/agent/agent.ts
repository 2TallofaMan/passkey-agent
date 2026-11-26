// The deterministic credential agent: root identity, dual-slot rotator, tiered policy engine,
// crash recovery, scheduler and zero-knowledge backup. No LLM / free-text interpretation anywhere.
import { useSyncExternalStore } from "react";

import { getRpKey, plain, resetRpKeyCache, RpError, signedGet, signedSend, WK } from "./api";
import * as C from "./crypto";
import { pwnedCount } from "./hibp";
import { idbAll, idbDelete, idbGet, idbPut, idbWipe } from "./idb";
import * as P from "./policy";
import * as WA from "./webauthn";

export type PhaseInfo = { domain: string; phase: string; step: number; total: number; pausedUntil: number | null };
export type AwsCreds = { accessKeyId: string; secretAccessKey: string };
export const AWS_DOMAIN = "aws.amazon.com";
export const SERVICES = [
  { domain: "northwind.bank", name: "Northwind Bank" },
  { domain: "acmemail.io", name: "Acme Mail" },
];

export type RotationState = "IDLE" | "STAGED" | "VERIFYING" | "DESYNC";
export type CrashPoint = "NONE" | "AFTER_STAGE" | "AFTER_REMOTE_UPDATE" | "AFTER_VERIFY" | "BEFORE_ACK";
export const CRASH_POINTS: { id: Exclude<CrashPoint, "NONE">; label: string; detail: string }[] = [
  { id: "AFTER_STAGE", label: "Crash after Stage", detail: "Staged slot committed locally, server never told" },
  { id: "AFTER_REMOTE_UPDATE", label: "Crash after Remote update", detail: "Server holds staged hash, local still STAGED" },
  { id: "AFTER_VERIFY", label: "Crash after Verify, before Commit", detail: "Server committed, local still VERIFYING" },
  { id: "BEFORE_ACK", label: "Crash before ACK purge", detail: "Both committed, old slot not yet purged on server" },
];

export type DomainRecord = {
  domain: string;
  slotActiveEncrypted: C.Sealed | null;
  slotStagedEncrypted: C.Sealed | null;
  rotationState: RotationState;
  rotationId: string | null;
  pendingAckRotationId: string | null;
  lastRotatedEpoch: number;
  rotationIntervalSeconds: number;
  trustedDeviceIdsJson: string;
  publicJwk: C.PublicJwk;
  rotationCount: number;
  serviceName?: string;
  username?: string;
  credentialType?: P.CredentialType;
  mode?: P.Mode | null;
  opModes?: Partial<Record<P.Operation, P.Mode>>;
  failureCount?: number;
  reminderSince?: number | null;
  custody?: "agent" | "user";
  stagedAt?: number | null;
  pendingDeleteKeyId?: string | null;
  lastVerification?: string | null;
  lastError: string | null;
};

export type Meta = {
  agentId: string;
  backupId: string;
  agentPublicJwk: C.PublicJwk;
  createdAt: number;
  tier2: WA.Tier2Credential | null;
  backupSyncEnabled: boolean;
  lastBackupAt: number | null;
  policy?: P.Policy;
  slowMoSeconds?: number;
};

export type Metric = { sessionsRevoked?: number; targetsConfirmed?: number; recoveryMs?: number };

export type AuditEvent = {
  id: string;
  ts: number;
  type: string;
  severity: "info" | "success" | "warning" | "error";
  tier: 0 | 1 | 2;
  domain: string | null;
  actor: string;
  detail: string;
  payloadSha256: string | null;
  metric?: Metric;
};

export type ApprovalRequest = {
  id: string;
  source: "remote" | "local";
  actionType: string;
  domain: string;
  humanReadableContext: string;
  requestingDevice: string;
  requestOriginIp: string;
  timestamp: number;
  payloadSha256: string;
  hashVerified: boolean;
};

export type SelfTest = { name: string; pass: boolean; detail: string };

type Snapshot = {
  status: "loading" | "unsupported" | "uninitialized" | "ready";
  meta: Meta | null;
  records: DomainRecord[];
  fingerprints: Record<string, { active: string | null; staged: string | null }>;
  approvals: ApprovalRequest[];
  terminal: string[];
  audit: AuditEvent[];
  busy: Record<string, boolean>;
  toast: { msg: string; kind: "info" | "success" | "error" } | null;
  allowSimulatedUV: boolean;
  lastTick: number;
  decisions: P.Decision[];
  phase: PhaseInfo | null;
  lastChaos: { point: string; pass: boolean; detail: string }[] | null;
  lastSelfTests: SelfTest[] | null;
  online: boolean;
};

export class ChaosCrash extends Error {}
const now = () => Math.floor(Date.now() / 1000);
const SLOT_AAD = (d: string) => `vault|${d}|slot`;
export const DEFAULT_INTERVAL = 1800; // 30 minutes
const TICK_MS = 15000;

class Agent {
  snap: Snapshot = {
    status: "loading",
    meta: null,
    records: [],
    fingerprints: {},
    approvals: [],
    terminal: [],
    audit: [],
    busy: {},
    toast: null,
    allowSimulatedUV: false,
    lastTick: 0,
    decisions: [],
    phase: null,
    lastChaos: null,
    lastSelfTests: null,
    online: true,
  };
  private listeners = new Set<() => void>();
  private domainKeys = new Map<string, CryptoKey>();
  private keyCache: { agent?: CryptoKey; vault?: CryptoKey; backup?: CryptoKey } = {};
  private locks = new Set<string>();
  private localResolvers = new Map<string, { resolve: (a: WA.Assertion) => void; reject: (e: Error) => void }>();
  private timers: ReturnType<typeof setInterval>[] = [];
  private toastTimer: ReturnType<typeof setTimeout> | null = null;
  private initStarted = false;

  subscribe = (fn: () => void) => {
    this.listeners.add(fn);
    return () => {
      this.listeners.delete(fn);
    };
  };
  getSnapshot = () => this.snap;
  private set(p: Partial<Snapshot>) {
    this.snap = { ...this.snap, ...p };
    this.listeners.forEach((l) => l());
  }

  toast(msg: string, kind: "info" | "success" | "error" = "info") {
    this.set({ toast: { msg, kind } });
    if (this.toastTimer) clearTimeout(this.toastTimer);
    this.toastTimer = setTimeout(() => this.set({ toast: null }), 3500);
  }

  term(line: string) {
    const t = new Date().toISOString().slice(11, 19);
    this.set({ terminal: [...this.snap.terminal.slice(-300), `[${t}] ${line}`] });
  }
  clearTerminal() {
    this.set({ terminal: [] });
  }

  async audit(e: Omit<AuditEvent, "id" | "ts" | "payloadSha256" | "actor" | "domain"> & Partial<AuditEvent>) {
    const ev: AuditEvent = {
      id: crypto.randomUUID(),
      ts: Date.now(),
      actor: "agent",
      domain: null,
      payloadSha256: null,
      ...e,
    } as AuditEvent;
    await idbPut("audit", `${ev.ts}-${ev.id}`, ev);
    this.set({ audit: [ev, ...this.snap.audit].slice(0, 1000) });
  }

  // ------------------------------------------------------------------ lifecycle
  async init() {
    if (this.initStarted) return;
    this.initStarted = true;
    if (typeof window === "undefined" || !globalThis.crypto?.subtle || typeof indexedDB === "undefined") {
      this.set({ status: "unsupported" });
      return;
    }
    const meta = await idbGet<Meta>("meta", "agent");
    if (!meta) {
      this.set({ status: "uninitialized" });
      return;
    }
    await this.boot(meta, "Application start");
  }

  private async boot(meta: Meta, reason: string) {
    const records = await idbAll<DomainRecord>("records");
    const audit = (await idbAll<AuditEvent>("audit")).sort((a, b) => b.ts - a.ts).slice(0, 1000);
    try {
      const k = await getRpKey();
      this.set({ allowSimulatedUV: !!k.allowSimulatedUV });
    } catch (e: any) {
      this.term(`RP key check failed: ${e.message}`);
    }
    this.set({ status: "ready", meta, records, audit });
    this.term(`${reason}: agent ${meta.agentId.slice(0, 8)} loaded ${records.length} record(s) from encrypted store`);
    await this.refreshFingerprints();
    await this.bootRecovery();
    this.startLoops();
  }

  private startLoops() {
    this.timers.forEach(clearInterval);
    this.timers = [setInterval(() => this.tick(), TICK_MS), setInterval(() => this.pollChallenges(), 8000)];
    if (typeof window !== "undefined" && !this.onlineBound) {
      this.onlineBound = true;
      window.addEventListener("online", () => {
        this.set({ online: true });
        this.term("Network back online: resuming any interrupted rotation");
        this.tick();
      });
      window.addEventListener("offline", () => this.set({ online: false }));
    }
    this.tick();
    this.pollChallenges();
  }
  private onlineBound = false;

  agentSend(path: string, body: object, method: "POST" | "PUT" = "POST") {
    return this.key("agent").then((k) => signedSend(method, path, body, this.agentId, k));
  }

  private stopLoops() {
    this.timers.forEach(clearInterval);
    this.timers = [];
  }

  // ------------------------------------------------------------------ keys
  private async key(name: "agent" | "vault" | "backup"): Promise<CryptoKey> {
    if (!this.keyCache[name]) {
      const k = await idbGet<CryptoKey>("keys", name);
      if (!k) throw new Error(`Key store missing ${name} key`);
      this.keyCache[name] = k;
    }
    return this.keyCache[name]!;
  }

  private async domainKey(domain: string): Promise<CryptoKey> {
    let k = this.domainKeys.get(domain);
    if (!k) {
      k = await idbGet<CryptoKey>("keys", `domain:${domain}`);
      if (!k) throw new Error(`No signing key for ${domain}`);
      this.domainKeys.set(domain, k);
    }
    return k;
  }

  private get agentId() {
    return this.snap.meta!.agentId;
  }

  private async domainPost(domain: string, path: string, body: object) {
    return signedSend("POST", path, body, this.agentId, await this.domainKey(domain));
  }

  // ------------------------------------------------------------------ onboarding / restore
  async onboard(mnemonic: string, passphrase: string, mode: "new" | "restore"): Promise<{ restoredDomains: number; backupFound: boolean }> {
    if (!C.isValidMnemonic(mnemonic) || C.wordCount(mnemonic) !== 24) throw new Error("Enter a valid 24-word BIP-39 phrase");
    const master = await C.deriveMasterKey(mnemonic, passphrase);
    const agentId = await C.deriveIdHex(master, "agent-id");
    const backupId = await C.deriveIdHex(master, "backup-id");
    const agentKp = await C.deriveSigningKey(master, "agent:identity");
    const vault = await C.deriveAesKey(master, "vault-encryption-key");
    const backup = await C.deriveAesKey(master, "backup-encryption-key");

    await idbPut("keys", "master", master);
    await idbPut("keys", "agent", agentKp.privateKey);
    await idbPut("keys", "vault", vault);
    await idbPut("keys", "backup", backup);
    this.keyCache = { agent: agentKp.privateKey, vault, backup };

    resetRpKeyCache();
    await getRpKey();
    await signedSend("POST", `${WK}/agent/register`, { agentId, publicKeyJwk: agentKp.publicJwk, timestamp: now() }, agentId, agentKp.privateKey);

    const meta: Meta = { agentId, backupId, agentPublicJwk: agentKp.publicJwk, createdAt: now(), tier2: null, backupSyncEnabled: false, lastBackupAt: null };
    let restoredDomains = 0;
    let backupFound = false;
    if (mode === "restore") {
      try {
        const b = await signedGet(`/backup/${backupId}`);
        backupFound = true;
        const pt = await C.open(backup, { iv: b.iv, ct: b.ciphertext }, `backup|${backupId}`);
        const snapshot = JSON.parse(C.fromUtf8(pt));
        pt.fill(0);
        meta.tier2 = snapshot.tier2 ?? null;
        meta.backupSyncEnabled = !!snapshot.backupSyncEnabled;
        meta.lastBackupAt = b.updatedAt;
        for (const rec of snapshot.records as DomainRecord[]) {
          const kp = await C.deriveSigningKey(master, `domain:${rec.domain}`);
          if (kp.publicJwk.x !== rec.publicJwk.x || kp.publicJwk.y !== rec.publicJwk.y) throw new Error(`Key mismatch for ${rec.domain}`);
          await idbPut("keys", `domain:${rec.domain}`, kp.privateKey);
          await idbPut("records", rec.domain, rec);
          restoredDomains++;
        }
      } catch (e: any) {
        if (!(e instanceof RpError && e.status === 404)) throw e;
      }
    }
    await idbPut("meta", "agent", meta);
    await this.audit({
      type: mode === "new" ? "ROOT_IDENTITY_CREATED" : "ROOT_IDENTITY_RESTORED",
      severity: "success",
      tier: 0,
      detail:
        mode === "new"
          ? "24-word seed -> PBKDF2-HMAC-SHA512 + HKDF-SHA256 root key wrapped as non-extractable; raw secrets zeroized"
          : `Restored from seed. Backup ${backupFound ? "found" : "not found"}; ${restoredDomains} domain(s) re-derived deterministically`,
    });
    await this.boot(meta, mode === "new" ? "Onboarding complete" : "Restore complete");
    return { restoredDomains, backupFound };
  }

  async wipeDevice() {
    this.stopLoops();
    this.domainKeys.clear();
    this.keyCache = {};
    resetRpKeyCache();
    await idbWipe();
    this.set({ status: "uninitialized", meta: null, records: [], fingerprints: {}, approvals: [], terminal: [], audit: [], busy: {} });
  }

  // ------------------------------------------------------------------ records
  private async putRecord(rec: DomainRecord) {
    await idbPut("records", rec.domain, rec); // resolves after durable commit
    this.set({ records: [...this.snap.records.filter((r) => r.domain !== rec.domain), rec].sort((a, b) => a.domain.localeCompare(b.domain)) });
  }

  private async readRecord(domain: string): Promise<DomainRecord> {
    const r = await idbGet<DomainRecord>("records", domain);
    if (!r) throw new Error(`Unknown domain ${domain}`);
    return r;
  }

  private async openSlot(s: C.Sealed | null, domain: string): Promise<Uint8Array | null> {
    return s ? C.open(await this.key("vault"), s, SLOT_AAD(domain)) : null;
  }

  async refreshFingerprints() {
    const fps: Snapshot["fingerprints"] = {};
    for (const r of this.snap.records) {
      const a = await this.openSlot(r.slotActiveEncrypted, r.domain);
      const s = await this.openSlot(r.slotStagedEncrypted, r.domain);
      fps[r.domain] = {
        active: a ? C.verifierFingerprint(await C.passwordVerifier(a, r.domain)) : null,
        staged: s ? C.verifierFingerprint(await C.passwordVerifier(s, r.domain)) : null,
      };
      a?.fill(0);
      s?.fill(0);
    }
    this.set({ fingerprints: fps });
  }

  async addDomain(domainRaw: string, devicesRaw: string, intervalSeconds = DEFAULT_INTERVAL) {
    const domain = domainRaw.trim().toLowerCase();
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) throw new Error("Enter a valid domain like example.com");
    if (this.snap.records.some((r) => r.domain === domain)) throw new Error("Domain already in vault");
    const devices = devicesRaw.split(",").map((d) => d.trim()).filter(Boolean);
    const master = await idbGet<CryptoKey>("keys", "master");
    if (!master) throw new Error("Root key missing");
    const kp = await C.deriveSigningKey(master, `domain:${domain}`);
    await idbPut("keys", `domain:${domain}`, kp.privateKey);
    this.domainKeys.set(domain, kp.privateKey);
    const pwd = C.randomPassword(64);
    const verifier = await C.passwordVerifier(pwd, domain);
    await this.domainPost(domain, `${WK}/enroll`, { domain, publicKeyJwk: kp.publicJwk, initialPasswordHash: verifier, trustedDevices: devices, timestamp: now() });
    const rec: DomainRecord = {
      domain,
      slotActiveEncrypted: await C.seal(await this.key("vault"), pwd, SLOT_AAD(domain)),
      slotStagedEncrypted: null,
      rotationState: "IDLE",
      rotationId: null,
      pendingAckRotationId: null,
      lastRotatedEpoch: now(),
      rotationIntervalSeconds: intervalSeconds,
      trustedDeviceIdsJson: JSON.stringify(devices),
      publicJwk: kp.publicJwk,
      rotationCount: 0,
      lastError: null,
    };
    pwd.fill(0);
    await this.putRecord(rec);
    await this.audit({ type: "DOMAIN_ENROLLED", severity: "success", tier: 1, domain, detail: `P-256 key = HKDF(master, "domain:${domain}"). Trusted: ${devices.join(", ") || "none"}` });
    await this.refreshFingerprints();
    this.syncBackup();
  }

  async removeDomain(domain: string) {
    await idbDelete("records", domain);
    await idbDelete("keys", `domain:${domain}`);
    this.domainKeys.delete(domain);
    this.set({ records: this.snap.records.filter((r) => r.domain !== domain) });
    await this.audit({ type: "DOMAIN_REMOVED", severity: "warning", tier: 1, domain, detail: "Removed from local vault" });
  }

  // ------------------------------------------------------------------ 4-phase rotation
  private crash(at: CrashPoint, here: CrashPoint) {
    if (at === here) throw new ChaosCrash(`Simulated process kill at ${here}`);
  }

  private async verifyPhase(domain: string, rotationId: string, pwd: Uint8Array, phase: "VERIFY_AND_COMMIT" | "PROBE" | "ACK_PURGE") {
    const ts = now();
    const candidatePasswordProof = await C.passwordProof(pwd, domain, rotationId, phase, ts);
    return this.domainPost(domain, `${WK}/rotate-verify`, { domain, rotationId, phase, candidatePasswordProof, purgePreviousSlot: false, timestamp: ts });
  }

  /** Cross-tab exclusive lock per domain (Web Locks API), so two tabs/schedulers never rotate the same record. */
  private async withDomainLock<T>(domain: string, busy: T, fn: () => Promise<T>): Promise<T> {
    const locks = (globalThis.navigator as any)?.locks;
    if (!locks?.request) return fn();
    return locks.request(`credential-agent:${domain}`, { ifAvailable: true }, async (lock: unknown) => (lock ? fn() : busy));
  }

  async rotate(domain: string, crashAt: CrashPoint = "NONE", reason = "manual"): Promise<boolean> {
    if (this.locks.has(domain)) throw new Error("Rotation already in progress");
    const ran = await this.withDomainLock<boolean | null>(domain, null, () => this.rotateLocked(domain, crashAt, reason));
    if (ran === null) {
      this.term(`[${domain}] skipped: another tab holds the rotation lock`);
      if (reason !== "scheduled") throw new Error("Rotation in progress in another tab");
      return false;
    }
    return ran;
  }

  async recoverRecord(domain: string): Promise<string> {
    return this.withDomainLock(domain, "LOCKED", () => this.recoverLocked(domain));
  }

  private async rotateLocked(domain: string, crashAt: CrashPoint, reason: string): Promise<boolean> {
    if (this.locks.has(domain)) return false;
    this.locks.add(domain);
    this.set({ busy: { ...this.snap.busy, [domain]: true } });
    let pwd: Uint8Array | null = null;
    try {
      let rec = await this.readRecord(domain);
      if (rec.rotationState !== "IDLE") throw new Error(`Record is ${rec.rotationState}; recovery must run first`);
      if (reason === "scheduled" && now() - rec.lastRotatedEpoch < rec.rotationIntervalSeconds) {
        await this.putRecord(rec); // another tab already rotated; refresh our view
        return true;
      }
      if (rec.credentialType === "aws_access_key") return await this.rotateAws(rec, crashAt, reason);
      const rotationId = crypto.randomUUID();
      this.term(`[${domain}] rotation ${rotationId.slice(0, 8)} start (${reason})`);
      // Phase 1: generate & stage (durable local commit, active untouched)
      pwd = C.randomPassword(64);
      rec = { ...rec, slotStagedEncrypted: await C.seal(await this.key("vault"), pwd, SLOT_AAD(domain)), rotationState: "STAGED", rotationId, lastError: null, stagedAt: Date.now() };
      await this.putRecord(rec);
      this.term(`[${domain}] phase 1 STAGE: staged slot committed, state=STAGED`);
      this.crash(crashAt, "AFTER_STAGE");
      await this.slow(domain, "STAGE", 1);
      // Phase 2: remote update (signed UV=false)
      const verifier = await C.passwordVerifier(pwd, domain);
      const trusted: string[] = JSON.parse(rec.trustedDeviceIdsJson);
      await this.domainPost(domain, `${WK}/rotate-stage`, {
        domain, rotationId, stagedPasswordHash: verifier, preserveTrustedSessions: trusted, userVerified: false, timestamp: now(),
      });
      this.term(`[${domain}] phase 2 REMOTE UPDATE: RP accepted staged hash (signed 200)`);
      this.crash(crashAt, "AFTER_REMOTE_UPDATE");
      await this.slow(domain, "REMOTE UPDATE", 2);
      // Phase 3: live verification
      rec = { ...rec, rotationState: "VERIFYING" };
      await this.putRecord(rec);
      const res = await this.verifyPhase(domain, rotationId, pwd, "VERIFY_AND_COMMIT");
      this.term(`[${domain}] phase 3 VERIFY: ${res.result}; preserved [${res.preservedSessions.join(", ")}] revoked [${res.revokedSessions.join(", ")}]`);
      const evidence = await this.realSignIn(rec, pwd);
      const view = await this.serverView(domain);
      const confirmed = view.sessions.filter((x: any) => trusted.includes(x.deviceId) && !x.revoked).length;
      this.term(`[${domain}] verified: ${evidence}; propagation: ${confirmed}/${trusted.length} trusted device sessions still active`);
      this.crash(crashAt, "AFTER_VERIFY");
      await this.slow(domain, "VERIFY + PROPAGATE", 3);
      // Phase 4: commit & purge
      rec = { ...rec, slotActiveEncrypted: rec.slotStagedEncrypted, slotStagedEncrypted: null, rotationState: "IDLE", rotationId: null, pendingAckRotationId: rotationId, lastRotatedEpoch: now(), rotationCount: rec.rotationCount + 1, failureCount: 0, stagedAt: null, lastVerification: evidence };
      await this.putRecord(rec);
      this.term(`[${domain}] phase 4 COMMIT: staged promoted to active, staged slot cleared`);
      this.crash(crashAt, "BEFORE_ACK");
      await this.verifyPhase(domain, rotationId, pwd, "ACK_PURGE");
      rec = { ...rec, pendingAckRotationId: null };
      await this.putRecord(rec);
      this.term(`[${domain}] ACK: previous password purged on RP. state=IDLE`);
      await this.audit({
        type: "PASSWORD_ROTATED", severity: "success", tier: 1, domain,
        detail: `Rotation ${rotationId.slice(0, 8)} (${reason}). Evidence: ${evidence}. Revoked: ${res.revokedSessions.join(", ") || "none"}`,
        metric: { sessionsRevoked: res.revokedSessions.length, targetsConfirmed: confirmed },
      });
      this.syncBackup();
      return true;
    } catch (e: any) {
      if (e instanceof ChaosCrash) {
        this.term(`[${domain}] !! ${e.message} - process terminated mid-rotation`);
        await this.audit({ type: "CHAOS_CRASH_INJECTED", severity: "warning", tier: 1, domain, detail: e.message });
      } else {
        await this.recordFailure(domain, e.message);
      }
      return false;
    } finally {
      pwd?.fill(0);
      this.locks.delete(domain);
      this.set({ busy: { ...this.snap.busy, [domain]: false }, phase: null });
      await this.refreshFingerprints();
    }
  }

  // ------------------------------------------------------------------ crash recovery
  private async recoverLocked(domain: string): Promise<string> {
    if (this.locks.has(domain)) return "LOCKED";
    this.locks.add(domain);
    let staged: Uint8Array | null = null;
    let active: Uint8Array | null = null;
    try {
      let rec = await this.readRecord(domain);
      if (rec.credentialType === "aws_access_key") return await this.recoverAws(rec);
      if (rec.rotationState === "IDLE") {
        if (rec.pendingAckRotationId) {
          active = await this.openSlot(rec.slotActiveEncrypted, domain);
          await this.verifyPhase(domain, rec.pendingAckRotationId, active!, "ACK_PURGE"); // throws -> stays pending, retried next tick
          await this.putRecord({ ...rec, pendingAckRotationId: null });
          this.term(`[${domain}] recovery: resent missing ACK purge`);
          return "ACK_RESENT";
        }
        return "CLEAN";
      }
      this.term(`[${domain}] recovery: found record stuck in ${rec.rotationState}; testing both slots against RP`);
      staged = await this.openSlot(rec.slotStagedEncrypted, domain);
      if (staged && rec.rotationId) {
        try {
          const r = await this.verifyPhase(domain, rec.rotationId, staged, "VERIFY_AND_COMMIT");
          const rid = rec.rotationId;
          rec = { ...rec, slotActiveEncrypted: rec.slotStagedEncrypted, slotStagedEncrypted: null, rotationState: "IDLE", rotationId: null, pendingAckRotationId: rid, lastRotatedEpoch: now(), rotationCount: rec.rotationCount + 1, lastError: null };
          await this.putRecord(rec);
          await this.verifyPhase(domain, rid, staged, "ACK_PURGE");
          await this.putRecord({ ...rec, pendingAckRotationId: null });
          this.term(`[${domain}] recovery: SLOT_STAGED valid (${r.result}) -> promoted, dead active slot wiped, state=IDLE`);
          await this.audit({ type: "CRASH_RECOVERY", severity: "success", tier: 1, domain, detail: `Kept STAGED slot (${r.result}); wiped stale active`, metric: { recoveryMs: this.recoveryMs(rec) } });
          return "KEPT_STAGED";
        } catch (e) {
          if (!(e instanceof RpError && e.status === 409)) throw e;
          this.term(`[${domain}] recovery: SLOT_STAGED rejected by RP (409)`);
        }
      }
      active = await this.openSlot(rec.slotActiveEncrypted, domain);
      const probe = await this.verifyPhase(domain, crypto.randomUUID(), active!, "PROBE");
      if (probe.matchedSlot === "ACTIVE") {
        await this.putRecord({ ...rec, slotStagedEncrypted: null, rotationState: "IDLE", rotationId: null, lastError: null });
        this.term(`[${domain}] recovery: SLOT_ACTIVE valid -> dead staged slot wiped, state=IDLE`);
        await this.audit({ type: "CRASH_RECOVERY", severity: "success", tier: 1, domain, detail: "Kept ACTIVE slot; wiped dead staged slot", metric: { recoveryMs: this.recoveryMs(rec) } });
        return "KEPT_ACTIVE";
      }
      await this.putRecord({ ...rec, rotationState: "DESYNC", lastError: "Neither slot verifies against RP" });
      await this.audit({ type: "KEYSTORE_DESYNC", severity: "error", tier: 1, domain, detail: "Neither slot verified" });
      return "DESYNC";
    } catch (e: any) {
      this.term(`[${domain}] recovery deferred: ${e.message}`);
      return "DEFERRED";
    } finally {
      staged?.fill(0);
      active?.fill(0);
      this.locks.delete(domain);
      await this.refreshFingerprints();
    }
  }

  async bootRecovery() {
    for (const r of this.snap.records) {
      if (r.rotationState === "STAGED" || r.rotationState === "VERIFYING" || r.pendingAckRotationId) await this.recoverRecord(r.domain);
    }
  }

  /** Simulates process death + restart: in-memory key handles dropped, state re-read from the encrypted store. */
  async simulateReboot() {
    this.stopLoops();
    this.domainKeys.clear();
    this.keyCache = {};
    this.locks.clear();
    this.term("=== SIMULATED REBOOT (BOOT_COMPLETED) ===");
    const meta = await idbGet<Meta>("meta", "agent");
    if (meta) await this.boot(meta, "Boot-time recovery scan");
  }

  async checkSync(domain: string): Promise<{ inSync: boolean; detail: string }> {
    const rec = await this.readRecord(domain);
    const active = await this.openSlot(rec.slotActiveEncrypted, domain);
    try {
      const probe = await this.verifyPhase(domain, crypto.randomUUID(), active!, "PROBE");
      const view = await plain("GET", `/rp/accounts/${this.agentId}/${domain}`);
      const inSync = probe.matchedSlot === "ACTIVE" && rec.rotationState === "IDLE" && !view.stagedFingerprint;
      return { inSync, detail: `local=${rec.rotationState} probe=${probe.matchedSlot} serverStaged=${view.stagedFingerprint ?? "none"}` };
    } finally {
      active?.fill(0);
    }
  }

  async serverView(domain: string) {
    return plain("GET", `/rp/accounts/${this.agentId}/${domain}`);
  }

  async runChaosSuite(domain: string): Promise<{ point: string; pass: boolean; detail: string }[]> {
    const out: { point: string; pass: boolean; detail: string }[] = [];
    this.term(`##### CHAOS SUITE on ${domain} #####`);
    for (const p of CRASH_POINTS) {
      await this.rotate(domain, p.id, `chaos:${p.id}`);
      await this.simulateReboot();
      const s = await this.checkSync(domain);
      out.push({ point: p.id, pass: s.inSync, detail: s.detail });
      this.term(`${s.inSync ? "PASS" : "FAIL"} ${p.id}: ${s.detail}`);
    }
    const all = out.every((o) => o.pass);
    await this.audit({ type: "CHAOS_SUITE", severity: all ? "success" : "error", tier: 1, domain, detail: `${out.filter((o) => o.pass).length}/${out.length} crash points recovered with zero desync` });
    return out;
  }

  // ------------------------------------------------------------------ scheduler (Task Scheduler equivalent)
  private async tick() {
    this.set({ lastTick: Date.now() });
    if (this.snap.status !== "ready" || (typeof navigator !== "undefined" && navigator.onLine === false)) return;
    for (const r of this.snap.records) {
      if (this.locks.has(r.domain)) continue;
      if (r.rotationState === "STAGED" || r.rotationState === "VERIFYING" || r.pendingAckRotationId) await this.recoverRecord(r.domain);
      else if (r.rotationState === "IDLE" && now() - r.lastRotatedEpoch >= r.rotationIntervalSeconds) await this.rotate(r.domain, "NONE", "scheduled");
    }
  }

  // ------------------------------------------------------------------ tiered policy engine
  private async pollChallenges() {
    if (this.snap.status !== "ready") return;
    try {
      const { challenges } = await plain("GET", `/rp/pending?agentId=${this.agentId}`);
      for (const ch of challenges) {
        if (!this.snap.records.some((r) => r.domain === ch.domain)) continue;
        if (ch.kind === "RESET") await this.autoRejectReset(ch);
        else if (ch.kind === "STEP_UP" && !this.snap.approvals.some((a) => a.id === ch.challengeId)) {
          const recomputed = await C.sha256Hex(C.utf8(C.canonicalJson(ch.payload)));
          const req: ApprovalRequest = {
            id: ch.challengeId, source: "remote", actionType: ch.payload.actionType, domain: ch.domain,
            humanReadableContext: ch.payload.humanReadableContext, requestingDevice: ch.payload.requestingDevice,
            requestOriginIp: ch.payload.requestOriginIp, timestamp: ch.payload.timestamp, payloadSha256: ch.payloadSha256,
            hashVerified: recomputed === ch.payloadSha256,
          };
          this.set({ approvals: [...this.snap.approvals, req] });
          await this.audit({ type: "TIER2_REQUESTED", severity: "warning", tier: 2, domain: ch.domain, actor: ch.payload.requestingDevice, detail: ch.payload.humanReadableContext, payloadSha256: ch.payloadSha256 });
        }
      }
    } catch {
      /* offline: retry next poll */
    }
  }

  private async autoRejectReset(ch: any) {
    // Deterministic rule: reset from an untrusted device is rejected without waking the user (Tier 1).
    await this.domainPost(ch.domain, `${WK}/recovery-challenge`, {
      domain: ch.domain, challengeId: ch.challengeId, requestOriginIp: ch.requestOriginIp, isTrustedDevice: false,
      action: "AUTO_REJECT_UNAUTHORIZED_RESET", timestamp: now(),
    });
    this.term(`[${ch.domain}] Tier 1: auto-rejected password reset from ${ch.requestingDevice} @ ${ch.requestOriginIp}`);
    await this.audit({ type: "RESET_AUTO_REJECTED", severity: "warning", tier: 1, domain: ch.domain, actor: `${ch.requestingDevice} (${ch.requestOriginIp})`, detail: "Unrecognized password-reset challenge rejected silently" });
  }

  async approve(id: string, mode: "hardware" | "simulated") {
    const req = this.snap.approvals.find((a) => a.id === id);
    if (!req) return;
    if (!req.hashVerified) throw new Error("Payload hash mismatch - refusing to sign");
    let assertion: WA.Assertion;
    if (mode === "hardware") {
      if (!this.snap.meta?.tier2) throw new Error("Enroll Windows Hello in Settings first");
      assertion = await WA.getTier2Assertion(this.snap.meta.tier2.credentialId, req.payloadSha256);
    } else assertion = { simulated: true };
    this.set({ approvals: this.snap.approvals.filter((a) => a.id !== id) });
    if (req.source === "local") {
      this.localResolvers.get(id)?.resolve(assertion);
      this.localResolvers.delete(id);
      return;
    }
    try {
      const res = await this.domainPost(req.domain, `${WK}/step-up`, {
        domain: req.domain, challengeId: req.id, actionType: req.actionType, humanReadableContext: req.humanReadableContext,
        payloadSha256: req.payloadSha256, requireUserVerification: true, decision: "APPROVE", assertion, timestamp: now(),
      });
      if (res.pairedDeviceId) {
        const rec = await this.readRecord(req.domain);
        const devs: string[] = JSON.parse(rec.trustedDeviceIdsJson);
        if (!devs.includes(res.pairedDeviceId)) await this.putRecord({ ...rec, trustedDeviceIdsJson: JSON.stringify([...devs, res.pairedDeviceId]) });
      }
      await this.audit({ type: "TIER2_APPROVED", severity: "success", tier: 2, domain: req.domain, actor: req.requestingDevice, detail: `${req.actionType} approved (UV=true, ${res.uvSource})`, payloadSha256: req.payloadSha256 });
      this.toast(`Approved ${req.actionType}`, "success");
    } catch (e: any) {
      await this.audit({ type: "TIER2_FAILED", severity: "error", tier: 2, domain: req.domain, detail: e.message, payloadSha256: req.payloadSha256 });
      throw e;
    }
  }

  async deny(id: string) {
    const req = this.snap.approvals.find((a) => a.id === id);
    if (!req) return;
    this.set({ approvals: this.snap.approvals.filter((a) => a.id !== id) });
    if (req.source === "local") {
      this.localResolvers.get(id)?.reject(new Error("Denied by user"));
      this.localResolvers.delete(id);
    } else {
      await this.domainPost(req.domain, `${WK}/step-up`, {
        domain: req.domain, challengeId: req.id, actionType: req.actionType, humanReadableContext: req.humanReadableContext,
        payloadSha256: req.payloadSha256, requireUserVerification: true, decision: "DENY", assertion: null, timestamp: now(),
      }).catch(() => null);
    }
    await this.audit({ type: "TIER2_DENIED", severity: "warning", tier: 2, domain: req.domain, actor: req.requestingDevice, detail: `${req.actionType} denied`, payloadSha256: req.payloadSha256 });
  }

  private requestLocalApproval(req: Omit<ApprovalRequest, "id" | "source" | "hashVerified">): Promise<WA.Assertion> {
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      this.localResolvers.set(id, { resolve, reject });
      this.set({ approvals: [...this.snap.approvals, { ...req, id, source: "local", hashVerified: true }] });
    });
  }

  async enrollTier2() {
    const cred = await WA.createTier2Credential(this.agentId);
    await signedSend("POST", `${WK}/tier2/register`, { agentId: this.agentId, ...cred, timestamp: now() }, this.agentId, await this.key("agent"));
    const meta = { ...this.snap.meta!, tier2: cred };
    await idbPut("meta", "agent", meta);
    this.set({ meta });
    await this.audit({ type: "TIER2_KEY_ENROLLED", severity: "success", tier: 2, detail: `Windows Hello credential (alg ${cred.alg}) bound to ${cred.rpId}` });
  }

  // ------------------------------------------------------------------ zero-knowledge backup
  private async buildBackup() {
    const meta = this.snap.meta!;
    const records = await idbAll<DomainRecord>("records");
    const snapshot = { version: 1, agentId: meta.agentId, exportedAt: now(), tier2: meta.tier2, backupSyncEnabled: true, records };
    const sealed = await C.seal(await this.key("backup"), C.utf8(JSON.stringify(snapshot)), `backup|${meta.backupId}`);
    const ciphertextSha256 = await C.sha256Hex(C.fromB64url(sealed.ct));
    return { sealed, ciphertextSha256, count: records.length };
  }

  async exportBackup() {
    const meta = this.snap.meta!;
    const { sealed, ciphertextSha256, count } = await this.buildBackup();
    const ts = now();
    const payload = { action: "EXPORT_ENCRYPTED_BACKUP", backupId: meta.backupId, ciphertextSha256, timestamp: ts };
    const payloadSha256 = await C.sha256Hex(C.utf8(C.canonicalJson(payload)));
    const assertion = await this.requestLocalApproval({
      actionType: "EXPORT_ENCRYPTED_BACKUP", domain: "(all domains)", humanReadableContext: `Upload AES-256-GCM encrypted snapshot of ${count} domain record(s)`,
      requestingDevice: "This browser", requestOriginIp: "local", timestamp: ts, payloadSha256,
    });
    const res = await signedSend("PUT", "/backup", {
      agentId: meta.agentId, backupId: meta.backupId, iv: sealed.iv, ciphertext: sealed.ct, ciphertextSha256, mode: "TIER2_EXPORT", assertion, timestamp: ts,
    }, meta.agentId, await this.key("agent"));
    const next = { ...meta, backupSyncEnabled: true, lastBackupAt: now() };
    await idbPut("meta", "agent", next);
    this.set({ meta: next });
    await this.audit({ type: "BACKUP_EXPORTED", severity: "success", tier: 2, detail: `${res.bytes} bytes ciphertext stored (UV ${res.uvSource}); auto-sync enabled`, payloadSha256 });
  }

  private async syncBackup() {
    const meta = this.snap.meta;
    if (!meta?.backupSyncEnabled) return;
    try {
      const { sealed, ciphertextSha256 } = await this.buildBackup();
      await signedSend("PUT", "/backup", {
        agentId: meta.agentId, backupId: meta.backupId, iv: sealed.iv, ciphertext: sealed.ct, ciphertextSha256, mode: "TIER1_SYNC", assertion: null, timestamp: now(),
      }, meta.agentId, await this.key("agent"));
      const next = { ...this.snap.meta!, lastBackupAt: now() };
      await idbPut("meta", "agent", next);
      this.set({ meta: next });
    } catch (e: any) {
      this.term(`backup sync failed: ${e.message}`);
    }
  }

  // ------------------------------------------------------------------ attack / RP simulations
  async simulate(kind: "rogue-session" | "reset-untrusted" | "reset-trusted" | "pairing" | "ownership", domain: string) {
    const rec = await this.readRecord(domain);
    const trusted: string[] = JSON.parse(rec.trustedDeviceIdsJson);
    const agentId = this.agentId;
    if (kind === "rogue-session") {
      const dev = `rogue-${Math.random().toString(36).slice(2, 6)}`;
      await plain("POST", "/rp/simulate/rogue-session", { agentId, domain, deviceId: dev });
      this.term(`[${domain}] RP: rogue session '${dev}' created (will be revoked on next rotation)`);
    } else if (kind === "reset-untrusted") {
      await plain("POST", "/rp/simulate/reset-request", { agentId, domain, deviceId: "unknown-device", originIp: "203.0.113.42" });
      this.term(`[${domain}] RP: password reset requested from 203.0.113.42 (untrusted)`);
    } else if (kind === "reset-trusted") {
      if (!trusted[0]) throw new Error("No trusted device on this domain");
      await plain("POST", "/rp/simulate/reset-request", { agentId, domain, deviceId: trusted[0], originIp: "198.51.100.7" });
      this.term(`[${domain}] RP: reset requested from trusted '${trusted[0]}' -> escalates to Tier 2`);
    } else {
      const pairing = kind === "pairing";
      await plain("POST", "/rp/simulate/step-up-request", {
        agentId, domain,
        actionType: pairing ? "AUTHORIZE_NEW_DEVICE_PAIRING" : "APPROVE_ACCOUNT_OWNERSHIP_CHANGE",
        humanReadableContext: pairing ? "Pair new device 'MacBook Pro (Vancouver, BC)'" : "Change account owner email to ops@example.org",
        requestingDevice: pairing ? "macbook-pro-vancouver" : "admin-console",
        requestOriginIp: pairing ? "24.85.12.190" : "192.0.2.15",
      });
      this.term(`[${domain}] RP: Tier 2 step-up issued (${pairing ? "device pairing" : "ownership change"})`);
    }
    setTimeout(() => this.pollChallenges(), 300);
  }

  // ------------------------------------------------------------------ self tests
  async runSelfTests(): Promise<SelfTest[]> {
    const out: SelfTest[] = [];
    const t = async (name: string, fn: () => Promise<string>) => {
      try {
        out.push({ name, pass: true, detail: await fn() });
      } catch (e: any) {
        out.push({ name, pass: false, detail: e.message });
      }
    };
    const vector = Array(23).fill("abandon").join(" ") + " art";
    await t("BIP-39 reference vector (24 words, TREZOR)", async () => {
      const h = await C.seedHex(vector, "TREZOR");
      if (!h.startsWith("bda85446c68413707090a52022edd26a")) throw new Error(`seed ${h.slice(0, 16)}...`);
      return "PBKDF2-HMAC-SHA512 seed matches published vector";
    });
    await t("Deterministic key restoration", async () => {
      const a = await C.deriveSigningKey(await C.deriveMasterKey(vector, "pw"), "domain:example.com");
      const b = await C.deriveSigningKey(await C.deriveMasterKey(vector, "pw"), "domain:example.com");
      const other = await C.deriveSigningKey(await C.deriveMasterKey(vector, "pw"), "domain:other.com");
      const pp = await C.deriveSigningKey(await C.deriveMasterKey(vector, "different"), "domain:example.com");
      if (a.publicJwk.x !== b.publicJwk.x || a.publicJwk.y !== b.publicJwk.y) throw new Error("same seed gave different keys");
      if (a.publicJwk.x === other.publicJwk.x) throw new Error("domains not isolated");
      if (a.publicJwk.x === pp.publicJwk.x) throw new Error("passphrase ignored");
      return `example.com key x=${a.publicJwk.x.slice(0, 10)}... reproduced; domains & passphrase isolated`;
    });
    await t("Encrypted backup restore from phrase", async () => {
      const k1 = await C.deriveAesKey(await C.deriveMasterKey(vector, ""), "backup-encryption-key");
      const k2 = await C.deriveAesKey(await C.deriveMasterKey(vector, ""), "backup-encryption-key");
      const sealed = await C.seal(k1, C.utf8('{"slot":"active"}'), "backup|test");
      const pt = C.fromUtf8(await C.open(k2, sealed, "backup|test"));
      if (pt !== '{"slot":"active"}') throw new Error("roundtrip mismatch");
      const bad = { ...sealed, ct: sealed.ct.slice(0, -2) + (sealed.ct.endsWith("A") ? "BB" : "AA") };
      let tamperDetected = false;
      await C.open(k2, bad, "backup|test").catch(() => (tamperDetected = true));
      if (!tamperDetected) throw new Error("tamper not detected");
      return "AES-256-GCM snapshot decrypts on re-derived key; tampering rejected";
    });
    await t("Signature over canonical JSON", async () => {
      const kp = await C.deriveSigningKey(await C.deriveMasterKey(vector, ""), "domain:example.com");
      const body = C.utf8(C.canonicalJson({ b: 1, a: [true, null], c: { z: "x", y: 2 } }));
      const sig = await C.signBytes(kp.privateKey, body);
      if (!(await C.verifyBytes(kp.publicJwk, sig, body))) throw new Error("verify failed");
      return "ECDSA P-256 signature verifies";
    });
    await t("Root key is non-extractable", async () => {
      const master = await idbGet<CryptoKey>("keys", "master");
      if (!master) throw new Error("no root key");
      if (master.extractable) throw new Error("root key extractable");
      let blocked = false;
      await crypto.subtle.exportKey("raw", master).catch(() => (blocked = true));
      if (!blocked) throw new Error("export succeeded");
      return "exportKey() refused by key store";
    });
    await t("Password generator", async () => {
      const p = C.randomPassword(64);
      const len = p.length;
      p.fill(0);
      if (len !== 64 || p.some((x) => x !== 0)) throw new Error("bad length or zeroize");
      return "64-char CSPRNG password; buffer zeroized after use";
    });
    await this.audit({ type: "SELF_TEST", severity: out.every((o) => o.pass) ? "success" : "error", tier: 0, detail: `${out.filter((o) => o.pass).length}/${out.length} passed` });
    return out;
  }
}

export const agent = new Agent();

export function useAgent() {
  return useSyncExternalStore(agent.subscribe, agent.getSnapshot, agent.getSnapshot);
}
