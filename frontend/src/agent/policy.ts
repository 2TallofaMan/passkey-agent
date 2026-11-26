// Deterministic policy engine: identical inputs always produce the identical decision. No model, no free text.
export type Mode = "FULLY_AUTOMATED" | "APPROVAL_REQUIRED" | "REMINDER_ONLY";
export type Operation = "ROTATE" | "NEW_DEVICE" | "BACKUP_EXPORT" | "OWNERSHIP_CHANGE";
export type TriggerKind = "SCHEDULE" | "EXPOSURE" | "SERVICE_NOTICE" | "USER_REQUEST";
export type CredentialType = "password" | "aws_access_key";
export type Policy = { default: Mode; operations: Partial<Record<Operation, Mode>> };

export const MODES: { id: Mode; label: string; short: string }[] = [
  { id: "FULLY_AUTOMATED", label: "Fully Automated", short: "AUTO" },
  { id: "APPROVAL_REQUIRED", label: "Approval Required", short: "APPROVAL" },
  { id: "REMINDER_ONLY", label: "Reminder Only", short: "REMIND" },
];
export const OPERATIONS: Operation[] = ["ROTATE", "NEW_DEVICE", "BACKUP_EXPORT", "OWNERSHIP_CHANGE"];
export const HIGH_RISK: Operation[] = ["NEW_DEVICE", "BACKUP_EXPORT", "OWNERSHIP_CHANGE"];
export const DEFAULT_POLICY: Policy = { default: "FULLY_AUTOMATED", operations: {} };
export const ESCALATE_AFTER_FAILURES = 3;

export type DecisionInput = {
  domain: string;
  credentialType: CredentialType;
  operation: Operation;
  trigger: TriggerKind;
  triggerDetail: string;
  accountMode: Mode | null;
  accountOps: Partial<Record<Operation, Mode>>;
  defaults: Policy;
  failureCount: number;
  serviceOutage: boolean;
  rotationState: string;
  custody: "agent" | "user";
};

export type Decision = {
  id: string;
  ts: number;
  inputsHash: string;
  domain: string;
  credentialType: CredentialType;
  operation: Operation;
  trigger: TriggerKind;
  triggerDetail: string;
  allowed: boolean;
  mode: Mode;
  modeSource: "operation" | "account" | "default-operation" | "default" | "high-risk floor" | "escalated";
  connector: string;
  verification: string[];
  recovery: string[];
  reason: string;
};

export function decide(i: DecisionInput): Omit<Decision, "id" | "ts" | "inputsHash"> {
  let mode: Mode;
  let modeSource: Decision["modeSource"];
  if (i.accountOps[i.operation]) [mode, modeSource] = [i.accountOps[i.operation]!, "operation"];
  else if (i.accountMode) [mode, modeSource] = [i.accountMode, "account"];
  else if (i.defaults.operations[i.operation]) [mode, modeSource] = [i.defaults.operations[i.operation]!, "default-operation"];
  else [mode, modeSource] = [i.defaults.default, "default"];

  if (HIGH_RISK.includes(i.operation) && mode !== "APPROVAL_REQUIRED") [mode, modeSource] = ["APPROVAL_REQUIRED", "high-risk floor"];
  if (i.operation === "ROTATE" && mode === "FULLY_AUTOMATED" && i.failureCount >= ESCALATE_AFTER_FAILURES)
    [mode, modeSource] = ["APPROVAL_REQUIRED", "escalated"];

  const aws = i.credentialType === "aws_access_key";
  const connector = aws ? "aws-iam: CreateAccessKey → STS → propagate → DeleteAccessKey" : "demo-service: agent passkey (P-256) + password slots";
  const verification = aws
    ? ["sts:GetCallerIdentity signed with the NEW key", "dependent app confirmed healthy on the new key"]
    : ["HMAC challenge-response proof of candidate (rotate-verify)", "real sign-in with the candidate password", "trusted sessions still active"];
  const recovery = [
    "on restart: probe both slots against the live service",
    "keep the working slot, delete the dead one",
    `retry; after ${ESCALATE_AFTER_FAILURES} failures escalate to Approval Required`,
    ...(aws ? ["delete orphaned keys (AWS 2-key limit)"] : []),
  ];

  let allowed = true;
  let reason = `${i.trigger} → ${i.operation} under ${mode} (${modeSource})`;
  if (i.custody === "user" && i.operation === "ROTATE") [allowed, reason] = [false, "Credential is user-managed since a manual change; re-enroll to hand it back"];
  else if (i.rotationState !== "IDLE" && i.operation === "ROTATE") [allowed, reason] = [false, `Record is ${i.rotationState}; recovery runs first`];
  else if (i.serviceOutage) [allowed, reason] = [false, "Service is offline; state kept, retry when it returns"];
  return { domain: i.domain, credentialType: i.credentialType, operation: i.operation, trigger: i.trigger, triggerDetail: i.triggerDetail, allowed, mode, modeSource, connector, verification, recovery, reason };
}
