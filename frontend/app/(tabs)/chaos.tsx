import { useEffect, useRef, useState } from "react";
import { Pressable, ScrollView, Text, useWindowDimensions, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { agent, CRASH_POINTS, CrashPoint, useAgent } from "@/src/agent/agent";
import { Badge, Btn, Card, Icon, ScreenHeader } from "@/src/components/ui";
import { usesNativeTabs } from "@/src/navigation";
import { fonts, makeStyles, radius, spacing, useTheme } from "@/src/theme";

type Sim = "rogue-session" | "reset-untrusted" | "reset-trusted" | "pairing" | "ownership";
const SIMS: { id: Sim; label: string; icon: any }[] = [
  { id: "reset-untrusted", label: "Reset from unknown IP (Tier 1 auto-reject)", icon: "account-alert" },
  { id: "rogue-session", label: "Inject rogue session (revoked on rotation)", icon: "incognito" },
  { id: "pairing", label: "New device pairing (Tier 2)", icon: "laptop" },
  { id: "ownership", label: "Account ownership change (Tier 2)", icon: "account-switch" },
  { id: "reset-trusted", label: "Reset from trusted device (Tier 2)", icon: "cellphone-key" },
];

export default function Chaos() {
  const s = useStyles();
  const { colors } = useTheme();
  const insets = useSafeAreaInsets();
  const { width } = useWindowDimensions();
  const { records, terminal } = useAgent();
  const [domain, setDomain] = useState<string | null>(null);
  const [point, setPoint] = useState<Exclude<CrashPoint, "NONE">>("AFTER_STAGE");
  const [busy, setBusy] = useState<string | null>(null);
  const [suite, setSuite] = useState<{ point: string; pass: boolean; detail: string }[] | null>(null);
  const termRef = useRef<any>(null);
  const split = width >= 1000;
  const bottomChrome = usesNativeTabs ? insets.bottom : 0;
  const d = domain && records.some((r) => r.domain === domain) ? domain : records[0]?.domain ?? null;
  const rec = records.find((r) => r.domain === d);

  useEffect(() => {
    termRef.current?.scrollToEnd({ animated: false });
  }, [terminal.length]);

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

  const controls = (
    <View style={{ gap: spacing.lg, flex: split ? 1 : undefined }}>
      <Card title="Target domain">
        {records.length === 0 ? (
          <Text testID="chaos-no-domains" style={s.muted}>Enroll a domain in the Vault first.</Text>
        ) : (
          <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={s.chips}>
            {records.map((r) => (
              <Pressable key={r.domain} testID={`chaos-domain-chip-${r.domain.replace(/[^a-z0-9]/g, "-")}`} onPress={() => setDomain(r.domain)} style={[s.chip, d === r.domain && s.chipOn]}>
                <Text style={[s.chipText, d === r.domain && s.chipTextOn]}>{r.domain}</Text>
              </Pressable>
            ))}
          </ScrollView>
        )}
        {rec ? (
          <View style={s.inline}>
            <Text style={s.muted}>Local state</Text>
            <Badge testID="chaos-domain-state" label={rec.rotationState} kind={rec.rotationState === "IDLE" ? "success" : rec.rotationState === "DESYNC" ? "error" : "warning"} />
          </View>
        ) : null}
      </Card>
      <Card title="Failure injection">
        {CRASH_POINTS.map((p) => (
          <Pressable key={p.id} testID={`crash-point-${p.id}`} onPress={() => setPoint(p.id)} style={[s.opt, point === p.id && s.optOn]}>
            <Icon name={point === p.id ? "radiobox-marked" : "radiobox-blank"} color={point === p.id ? colors.brandPrimary : colors.muted} />
            <View style={{ flex: 1 }}>
              <Text style={s.optTitle}>{p.label}</Text>
              <Text style={s.muted}>{p.detail}</Text>
            </View>
          </Pressable>
        ))}
        <View style={s.btns}>
          <Btn testID="chaos-inject-crash-btn" label="Rotate & crash" icon="flash-alert" disabled={!d || rec?.rotationState !== "IDLE"} loading={busy === "crash"} onPress={() => run("crash", async () => { await agent.rotate(d!, point, `chaos:${point}`); })} />
          <Btn testID="chaos-reboot-btn" label="Simulate reboot" variant="secondary" icon="restart" disabled={!d} loading={busy === "reboot"} onPress={() => run("reboot", () => agent.simulateReboot())} />
          <Btn testID="chaos-check-sync-btn" label="Check sync" variant="ghost" icon="sync" disabled={!d} loading={busy === "sync"} onPress={() => run("sync", async () => { const r = await agent.checkSync(d!); agent.term(`[${d}] SYNC ${r.inSync ? "OK" : "DESYNC"}: ${r.detail}`); })} />
        </View>
        <Btn testID="chaos-run-suite-btn" label="Run full chaos suite (all 4 crash points)" icon="test-tube" disabled={!d || rec?.rotationState !== "IDLE"} loading={busy === "suite"} onPress={() => run("suite", async () => setSuite(await agent.runChaosSuite(d!)))} />
        {suite ? (
          <View testID="chaos-suite-results" style={{ gap: spacing.xs }}>
            {suite.map((r) => (
              <View key={r.point} style={s.inline}>
                <Badge testID={`chaos-suite-result-${r.point}`} label={r.pass ? "PASS" : "FAIL"} kind={r.pass ? "success" : "error"} />
                <Text style={s.mono}>{r.point}</Text>
              </View>
            ))}
          </View>
        ) : null}
      </Card>
      <Card title="Attack & RP simulations">
        {SIMS.map((x) => (
          <Btn key={x.id} testID={`sim-${x.id}-btn`} label={x.label} variant="secondary" icon={x.icon} compact disabled={!d} loading={busy === x.id} onPress={() => run(x.id, () => agent.simulate(x.id, d!))} style={{ justifyContent: "flex-start" }} />
        ))}
      </Card>
    </View>
  );

  const term = (
    <View style={[s.term, split ? { flex: 1.2 } : { height: 420 }]}>
      <View style={s.termHead}>
        <Text style={s.termTitle}>agent.log — live</Text>
        <Pressable testID="terminal-clear-btn" onPress={() => agent.clearTerminal()}>
          <Text style={s.muted}>clear</Text>
        </Pressable>
      </View>
      <ScrollView ref={termRef} testID="chaos-terminal" contentContainerStyle={{ padding: spacing.md }}>
        {terminal.length === 0 ? <Text style={s.termLine}>$ select a failure mode to inject…</Text> : null}
        {terminal.map((l, i) => (
          <Text key={i} style={[s.termLine, /PASS|SYNC OK|IDLE|promoted|wiped/.test(l) && { color: colors.successText }, /!!|FAIL|DESYNC|error/.test(l) && { color: colors.errorText }]}>
            {l}
          </Text>
        ))}
      </ScrollView>
    </View>
  );

  return (
    <View style={s.root}>
      <ScreenHeader title="Chaos Lab" subtitle="Kill the process mid-rotation, reboot, prove zero keystore desync" />
      <ScrollView contentContainerStyle={[s.content, { paddingBottom: bottomChrome + spacing.xl }]}>
        <View style={[s.split, { flexDirection: split ? "row" : "column" }]}>
          {controls}
          {term}
        </View>
      </ScrollView>
    </View>
  );
}

const useStyles = makeStyles((c) => ({
  root: { flex: 1, backgroundColor: c.surface },
  content: { padding: spacing.xl, width: "100%", maxWidth: 1400, alignSelf: "center" },
  split: { gap: spacing.lg, alignItems: "stretch" },
  chips: { gap: spacing.sm, height: 56, alignItems: "center" },
  chip: { height: 36, flexShrink: 0, paddingHorizontal: spacing.md, borderRadius: radius.pill, borderWidth: 1, borderColor: c.border, backgroundColor: c.surfaceTertiary, justifyContent: "center" },
  chipOn: { borderColor: c.brandPrimary, backgroundColor: c.brandTertiary },
  chipText: { color: c.onSurfaceTertiary, fontSize: 13, fontFamily: fonts.mono },
  chipTextOn: { color: c.onBrandTertiary },
  opt: { flexDirection: "row", gap: spacing.md, alignItems: "center", padding: spacing.md, borderRadius: radius.sm, borderWidth: 1, borderColor: c.border },
  optOn: { borderColor: c.brandPrimary },
  optTitle: { color: c.onSurface, fontSize: 14, fontWeight: "700" },
  muted: { color: c.muted, fontSize: 12 },
  mono: { color: c.onSurfaceTertiary, fontSize: 12, fontFamily: fonts.mono },
  btns: { flexDirection: "row", gap: spacing.sm, flexWrap: "wrap" },
  inline: { flexDirection: "row", gap: spacing.sm, alignItems: "center" },
  term: { backgroundColor: c.surfaceTertiary, borderRadius: radius.md, borderWidth: 1, borderColor: c.border, overflow: "hidden", minHeight: 420 },
  termHead: { flexDirection: "row", justifyContent: "space-between", padding: spacing.md, borderBottomWidth: 1, borderBottomColor: c.border },
  termTitle: { color: c.onSurface, fontFamily: fonts.mono, fontSize: 12, fontWeight: "700" },
  termLine: { color: c.onSurfaceSecondary, fontFamily: fonts.mono, fontSize: 12, lineHeight: 18 },
}));
