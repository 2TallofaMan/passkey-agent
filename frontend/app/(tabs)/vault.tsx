import { useEffect, useState } from "react";
import { ScrollView, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { agent, DEFAULT_INTERVAL, DomainRecord, useAgent } from "@/src/agent/agent";
import { Badge, Btn, Card, Field, Icon, ScreenHeader } from "@/src/components/ui";
import { usesNativeTabs } from "@/src/navigation";
import { fonts, makeStyles, radius, spacing, useTheme } from "@/src/theme";

function useNow() {
  const [n, setN] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setN(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return n;
}

const fmtDur = (sec: number) => {
  if (sec <= 0) return "due";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
};

const stateKind = (s: DomainRecord["rotationState"]) => (s === "IDLE" ? "success" : s === "DESYNC" ? "error" : "warning");

function DomainRow({ rec, now }: { rec: DomainRecord; now: number }) {
  const s = useStyles();
  const { colors } = useTheme();
  const { fingerprints, busy } = useAgent();
  const fp = fingerprints[rec.domain];
  const [sync, setSync] = useState<{ inSync: boolean; detail: string } | null>(null);
  const [view, setView] = useState<any | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const id = rec.domain.replace(/[^a-z0-9]/g, "-");
  const devices: string[] = JSON.parse(rec.trustedDeviceIdsJson);
  const next = rec.lastRotatedEpoch + rec.rotationIntervalSeconds - Math.floor(now / 1000);

  const act = async (k: string, fn: () => Promise<void>) => {
    setLoading(k);
    try {
      await fn();
    } catch (e: any) {
      agent.toast(e.message, "error");
    } finally {
      setLoading(null);
    }
  };

  return (
    <View testID={`domain-row-${id}`} style={s.row}>
      <View style={s.rowHead}>
        <Icon name="web" color={colors.brandPrimary} />
        <Text testID={`domain-name-${id}`} style={s.domain}>
          {rec.domain}
        </Text>
        <Badge testID={`domain-state-${id}`} label={rec.rotationState} kind={stateKind(rec.rotationState)} />
        <View style={{ flex: 1 }} />
        <Btn compact testID={`domain-rotate-btn-${id}`} label="Rotate now" icon="rotate-right" loading={busy[rec.domain] || loading === "rotate"} disabled={rec.rotationState !== "IDLE"} onPress={() => act("rotate", async () => { const ok = await agent.rotate(rec.domain); agent.toast(ok ? `${rec.domain} rotated` : "Rotation failed - see audit", ok ? "success" : "error"); })} />
        <Btn compact variant="secondary" testID={`domain-sync-btn-${id}`} label="Check sync" icon="sync" loading={loading === "sync"} onPress={() => act("sync", async () => setSync(await agent.checkSync(rec.domain)))} />
        <Btn compact variant="ghost" testID={`domain-server-btn-${id}`} label={view ? "Hide RP" : "RP view"} icon="server" loading={loading === "view"} onPress={() => act("view", async () => setView(view ? null : await agent.serverView(rec.domain)))} />
      </View>
      <View style={s.cells}>
        <Cell label="Slot A · Active" value={fp?.active ?? "—"} testID={`domain-slot-active-${id}`} tone="success" />
        <Cell label="Slot B · Staged" value={fp?.staged ?? "empty"} testID={`domain-slot-staged-${id}`} tone={fp?.staged ? "warning" : "muted"} />
        <Cell label="Last rotated" value={new Date(rec.lastRotatedEpoch * 1000).toLocaleTimeString()} testID={`domain-last-rotated-${id}`} />
        <Cell label="Next rotation" value={fmtDur(next)} testID={`domain-next-rotation-${id}`} tone="brand" />
        <Cell label="Rotations" value={String(rec.rotationCount)} testID={`domain-rotation-count-${id}`} />
        <Cell label="Interval" value={`${Math.round(rec.rotationIntervalSeconds / 60)} min`} />
      </View>
      <Text style={s.devices} testID={`domain-trusted-${id}`}>
        Preserved sessions: {devices.length ? devices.join(" · ") : "none"}
      </Text>
      {rec.lastError ? <Text style={s.err} testID={`domain-error-${id}`}>Last error: {rec.lastError}</Text> : null}
      {sync ? (
        <View style={s.inline}>
          <Badge testID={`domain-sync-result-${id}`} label={sync.inSync ? "IN SYNC" : "DESYNC"} kind={sync.inSync ? "success" : "error"} />
          <Text style={s.mono}>{sync.detail}</Text>
        </View>
      ) : null}
      {view ? (
        <View style={s.rp} testID={`domain-rp-view-${id}`}>
          <Text style={s.rpTitle}>Relying Party view (mock server)</Text>
          <Text style={s.mono}>
            active={view.activeFingerprint} staged={view.stagedFingerprint ?? "none"} previousSlot={view.previousSlotPresent ? "present" : "purged"} rotations={view.rotations}
          </Text>
          {view.sessions.map((x: any, i: number) => (
            <View key={i} style={s.inline}>
              <Badge label={x.revoked ? "REVOKED" : x.trusted ? "TRUSTED" : "UNTRUSTED"} kind={x.revoked ? "error" : x.trusted ? "success" : "warning"} />
              <Text style={s.mono}>{x.deviceId}</Text>
            </View>
          ))}
        </View>
      ) : null}
    </View>
  );
}

function Cell({ label, value, testID, tone }: { label: string; value: string; testID?: string; tone?: "success" | "warning" | "brand" | "muted" }) {
  const s = useStyles();
  const { colors } = useTheme();
  const color = tone === "success" ? colors.successText : tone === "warning" ? colors.warning : tone === "brand" ? colors.brandPrimary : tone === "muted" ? colors.muted : colors.onSurface;
  return (
    <View style={s.cell}>
      <Text style={s.cellLabel}>{label}</Text>
      <Text testID={testID} style={[s.cellValue, { color }]}>
        {value}
      </Text>
    </View>
  );
}

export default function Vault() {
  const s = useStyles();
  const insets = useSafeAreaInsets();
  const { records, meta, approvals } = useAgent();
  const now = useNow();
  const [domain, setDomain] = useState("example.com");
  const [devices, setDevices] = useState("surface-laptop-7, living-room-tv");
  const [adding, setAdding] = useState(false);
  const bottomChrome = usesNativeTabs ? insets.bottom : 0;

  const add = async () => {
    setAdding(true);
    try {
      await agent.addDomain(domain, devices, DEFAULT_INTERVAL);
      agent.toast(`${domain} enrolled`, "success");
      setDomain("");
    } catch (e: any) {
      agent.toast(e.message, "error");
    } finally {
      setAdding(false);
    }
  };

  return (
    <View style={s.root}>
      <ScreenHeader
        title="Domain Vault"
        subtitle={meta ? `agent ${meta.agentId.slice(0, 12)} · Tier 2 ${meta.tier2 ? "enrolled" : "not enrolled"} · rotates every 30 min` : ""}
        right={approvals.length ? <Badge testID="vault-pending-approvals" label={`${approvals.length} APPROVAL PENDING`} kind="warning" /> : undefined}
      />
      <ScrollView contentContainerStyle={[s.content, { paddingBottom: bottomChrome + spacing.xl }]} keyboardShouldPersistTaps="handled">
        <Card title="Enroll domain" testID="add-domain-card">
          <View style={s.form}>
            <Field testID="add-domain-input" label="Domain" value={domain} onChangeText={setDomain} placeholder="example.com" />
            <Field testID="add-devices-input" label="Trusted devices (comma separated)" value={devices} onChangeText={setDevices} />
            <Btn testID="add-domain-btn" label="Enroll" icon="plus" loading={adding} onPress={add} />
          </View>
        </Card>
        {records.length === 0 ? (
          <View style={s.empty} testID="vault-empty">
            <Icon name="safe" size={40} />
            <Text style={s.emptyText}>No domains yet. Enroll one above to start dual-slot rotation.</Text>
          </View>
        ) : (
          records.map((r) => <DomainRow key={r.domain} rec={r} now={now} />)
        )}
      </ScrollView>
    </View>
  );
}

const useStyles = makeStyles((c) => ({
  root: { flex: 1, backgroundColor: c.surface },
  content: { padding: spacing.xl, gap: spacing.lg, width: "100%", maxWidth: 1200, alignSelf: "center" },
  form: { flexDirection: "row", gap: spacing.md, flexWrap: "wrap", alignItems: "flex-end" },
  row: { backgroundColor: c.surfaceSecondary, borderWidth: 1, borderColor: c.border, borderRadius: radius.md, padding: spacing.lg, gap: spacing.md },
  rowHead: { flexDirection: "row", alignItems: "center", gap: spacing.sm, flexWrap: "wrap" },
  domain: { color: c.onSurface, fontSize: 18, fontWeight: "800", fontFamily: fonts.mono },
  cells: { flexDirection: "row", flexWrap: "wrap", borderTopWidth: 1, borderTopColor: c.divider, paddingTop: spacing.md },
  cell: { minWidth: 150, flex: 1, gap: 2, paddingVertical: spacing.xs },
  cellLabel: { color: c.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.6 },
  cellValue: { fontFamily: fonts.mono, fontSize: 15, fontWeight: "700" },
  devices: { color: c.onSurfaceTertiary, fontSize: 12, fontFamily: fonts.mono },
  err: { color: c.errorText, fontSize: 12, fontFamily: fonts.mono },
  inline: { flexDirection: "row", gap: spacing.sm, alignItems: "center", flexWrap: "wrap" },
  mono: { color: c.onSurfaceTertiary, fontSize: 12, fontFamily: fonts.mono, flexShrink: 1 },
  rp: { backgroundColor: c.surfaceTertiary, borderRadius: radius.sm, padding: spacing.md, gap: spacing.sm },
  rpTitle: { color: c.onSurface, fontSize: 12, fontWeight: "800", textTransform: "uppercase", letterSpacing: 0.8 },
  empty: { alignItems: "center", padding: spacing.xxxl, gap: spacing.md },
  emptyText: { color: c.muted, fontSize: 14, textAlign: "center" },
}));
