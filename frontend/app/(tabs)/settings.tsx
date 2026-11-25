import { useRouter } from "expo-router";
import { useEffect, useState } from "react";
import { Modal, ScrollView, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { agent, SelfTest, useAgent } from "@/src/agent/agent";
import { platformAuthenticatorAvailable, webauthnSupported } from "@/src/agent/webauthn";
import { Badge, Btn, Card, KV, ScreenHeader } from "@/src/components/ui";
import { usesNativeTabs } from "@/src/navigation";
import { makeStyles, radius, spacing } from "@/src/theme";

export default function Settings() {
  const s = useStyles();
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const { meta, allowSimulatedUV } = useAgent();
  const [platformOk, setPlatformOk] = useState<boolean | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [tests, setTests] = useState<SelfTest[] | null>(null);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const bottomChrome = usesNativeTabs ? insets.bottom : 0;

  useEffect(() => {
    platformAuthenticatorAvailable().then(setPlatformOk);
  }, []);

  const run = async (k: string, fn: () => Promise<void>) => {
    setBusy(k);
    try {
      await fn();
    } catch (e: any) {
      agent.toast(e.message, "error");
    } finally {
      setBusy(null);
    }
  };

  if (!meta) return <View style={s.root} />;

  return (
    <View style={s.root}>
      <ScreenHeader title="Settings" subtitle="Root identity · Tier 2 hardware key · backup · self-tests" />
      <ScrollView contentContainerStyle={[s.content, { paddingBottom: bottomChrome + spacing.xl }]}>
        <Card title="Root identity" testID="identity-card">
          <KV k="Agent ID" v={meta.agentId} mono testID="settings-agent-id" />
          <KV k="Backup slot ID" v={meta.backupId} mono testID="settings-backup-id" />
          <KV k="Agent key (P-256)" v={`x=${meta.agentPublicJwk.x.slice(0, 22)}…`} mono />
          <KV k="Key store" v="Non-extractable WebCrypto keys in the browser profile (the page can use keys, never read them). Hardware TPM via Windows Hello for Tier 2." />
          <KV k="Derivation" v="BIP-39 seed (PBKDF2-HMAC-SHA512) → HKDF-SHA256 master → HKDF('domain:<name>') per-domain keys" />
        </Card>

        <Card title="Tier 2 · Windows Hello" testID="tier2-card" right={<Badge testID="tier2-status" label={meta.tier2 ? "ENROLLED" : "NOT ENROLLED"} kind={meta.tier2 ? "success" : "warning"} />}>
          <Text style={s.p}>
            High-risk actions (device pairing, backup export, ownership change, step-up challenges) require a WebAuthn assertion with User Verification from your platform authenticator — Windows Hello
            fingerprint/face/PIN on Windows, Touch ID on Mac, fingerprint/face on phones. The assertion challenge is the exact payload SHA-256.
          </Text>
          <KV k="Platform authenticator" v={!webauthnSupported() ? "WebAuthn unsupported" : platformOk === null ? "checking…" : platformOk ? "available" : "not detected"} testID="tier2-platform-status" />
          {meta.tier2 ? <KV k="Credential" v={`${meta.tier2.credentialId.slice(0, 24)}… · alg ${meta.tier2.alg} · ${meta.tier2.rpId}`} mono /> : null}
          <Btn testID="tier2-enroll-btn" label={meta.tier2 ? "Re-enroll Windows Hello" : "Enroll Windows Hello"} icon="fingerprint" loading={busy === "enroll"} onPress={() => run("enroll", async () => { await agent.enrollTier2(); agent.toast("Windows Hello key enrolled", "success"); })} />
          <Text style={s.hint}>If the biometric prompt is blocked, open the app in its own browser tab (preview frames block WebAuthn).</Text>
          {allowSimulatedUV ? <Text style={s.hint}>Test mode: the mock server also accepts clearly-labelled simulated approvals.</Text> : null}
        </Card>

        <Card title="Zero-knowledge backup" testID="backup-card" right={<Badge testID="backup-status" label={meta.backupSyncEnabled ? "AUTO-SYNC ON" : "NOT EXPORTED"} kind={meta.backupSyncEnabled ? "success" : "warning"} />}>
          <Text style={s.p}>
            Snapshot of all dual-slot records, encrypted with AES-256-GCM using a key derived from your seed. The server only ever sees ciphertext. First export needs Tier 2; afterwards every rotation
            auto-syncs (Tier 1) so a replacement device restores live passwords from the 24 words alone.
          </Text>
          <KV k="Last backup" v={meta.lastBackupAt ? new Date(meta.lastBackupAt * 1000).toLocaleString() : "never"} testID="backup-last" />
          <Btn testID="backup-export-btn" label="Export encrypted backup" icon="cloud-lock" loading={busy === "backup"} onPress={() => run("backup", async () => { await agent.exportBackup(); agent.toast("Encrypted backup stored", "success"); })} />
        </Card>

        <Card title="Background rotation" testID="scheduler-card">
          <Text style={s.p}>
            Each domain rotates every 30 minutes. The scheduler runs while this tab is open (checked every 15 s, network required) and catches up on overdue rotations and stuck records the moment the
            app opens — the closest a web page gets to WorkManager / Windows Task Scheduler.
          </Text>
        </Card>

        <Card title="Cryptographic self-tests" testID="selftest-card">
          <Btn testID="selftest-run-btn" label="Run self-tests" icon="test-tube" variant="secondary" loading={busy === "tests"} onPress={() => run("tests", async () => setTests(await agent.runSelfTests()))} />
          {tests?.map((t, i) => (
            <View key={i} style={s.test}>
              <Badge testID={`selftest-result-${i}`} label={t.pass ? "PASS" : "FAIL"} kind={t.pass ? "success" : "error"} />
              <View style={{ flex: 1 }}>
                <Text style={s.testName}>{t.name}</Text>
                <Text style={s.hint}>{t.detail}</Text>
              </View>
            </View>
          ))}
        </Card>

        <Card title="Simulate hardware loss" danger testID="wipe-card">
          <Text style={s.p}>Wipes every key and record from this browser. Restore afterwards with your 24-word phrase to prove deterministic recovery.</Text>
          <Btn testID="wipe-device-btn" label="Wipe this device" variant="danger" icon="delete-forever" onPress={() => setConfirmWipe(true)} />
        </Card>
      </ScrollView>

      <Modal visible={confirmWipe} transparent animationType="fade" onRequestClose={() => setConfirmWipe(false)}>
        <View style={s.backdrop}>
          <View style={s.dialog} testID="wipe-confirm-dialog">
            <Text style={s.dialogTitle}>Wipe all local keys?</Text>
            <Text style={s.p}>Without your 24-word phrase this agent cannot be recovered.</Text>
            <View style={{ flexDirection: "row", gap: spacing.md }}>
              <Btn testID="wipe-cancel-btn" label="Cancel" variant="ghost" onPress={() => setConfirmWipe(false)} />
              <Btn
                testID="wipe-confirm-btn"
                label="Wipe"
                variant="danger"
                loading={busy === "wipe"}
                style={{ flexGrow: 1 }}
                onPress={() => run("wipe", async () => { await agent.wipeDevice(); setConfirmWipe(false); router.replace("/onboarding"); })}
              />
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const useStyles = makeStyles((c) => ({
  root: { flex: 1, backgroundColor: c.surface },
  content: { padding: spacing.xl, gap: spacing.lg, width: "100%", maxWidth: 900, alignSelf: "center" },
  p: { color: c.onSurfaceTertiary, fontSize: 13, lineHeight: 19 },
  hint: { color: c.muted, fontSize: 12 },
  test: { flexDirection: "row", gap: spacing.md, alignItems: "flex-start" },
  testName: { color: c.onSurface, fontSize: 13, fontWeight: "700" },
  backdrop: { flex: 1, backgroundColor: c.overlay, alignItems: "center", justifyContent: "center", padding: spacing.xl },
  dialog: { width: "100%", maxWidth: 420, backgroundColor: c.surfaceSecondary, borderRadius: radius.md, borderWidth: 1, borderColor: c.error, padding: spacing.xl, gap: spacing.lg },
  dialogTitle: { color: c.onSurface, fontSize: 18, fontWeight: "800" },
}));
