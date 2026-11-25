import { Image } from "expo-image";
import { useState } from "react";
import { Modal, Pressable, ScrollView, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { agent, useAgent } from "@/src/agent/agent";
import { Badge, Btn, Icon, KV } from "@/src/components/ui";
import { fonts, makeStyles, radius, spacing, useTheme } from "@/src/theme";

const BIO_IMG =
  "https://images.unsplash.com/photo-1611330500121-d9439ddc3d9d?crop=entropy&cs=srgb&fm=jpg&q=60&w=900";

export function ApprovalSheet() {
  const s = useStyles();
  const { colors } = useTheme();
  const insets = useSafeAreaInsets();
  const { approvals, meta, allowSimulatedUV } = useAgent();
  const req = approvals[0];
  const [busy, setBusy] = useState<"hardware" | "simulated" | "deny" | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const run = async (mode: "hardware" | "simulated" | "deny") => {
    if (!req) return;
    setBusy(mode);
    setErr(null);
    try {
      if (mode === "deny") await agent.deny(req.id);
      else await agent.approve(req.id, mode);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Modal visible={!!req} transparent animationType="slide" onRequestClose={() => req && run("deny")}>
      <View style={s.backdrop}>
        {req ? (
          <View testID="tier2-approval-sheet" style={[s.sheet, { paddingBottom: insets.bottom + spacing.xl }]}>
            <ScrollView contentContainerStyle={{ gap: spacing.lg }}>
              <View style={s.top}>
                <Image source={{ uri: BIO_IMG }} style={s.img} contentFit="cover" />
                <View style={{ flex: 1, gap: spacing.xs }}>
                  <Badge label="TIER 2 · HARDWARE STEP-UP" kind="brand" />
                  <Text style={s.title}>Transaction-bound approval</Text>
                  <Text style={s.sub}>
                    Windows Hello signs exactly this payload hash. Nothing else can be approved with this tap.
                  </Text>
                </View>
                {approvals.length > 1 ? <Badge testID="approval-queue-count" label={`+${approvals.length - 1} QUEUED`} kind="warning" /> : null}
              </View>
              <View style={s.box}>
                <KV k="Action" v={req.actionType} mono testID="approval-action" />
                <KV k="Domain" v={req.domain} mono testID="approval-domain" />
                <KV k="Context" v={req.humanReadableContext} testID="approval-context" />
                <KV k="Device / IP" v={`${req.requestingDevice} · ${req.requestOriginIp}`} mono testID="approval-device" />
                <KV k="Timestamp" v={new Date(req.timestamp * 1000).toISOString()} mono testID="approval-timestamp" />
                <KV k="Payload SHA-256" v={req.payloadSha256} mono testID="approval-payload-hash" />
              </View>
              <View style={s.row}>
                <Icon name={req.hashVerified ? "shield-check" : "shield-alert"} color={req.hashVerified ? colors.successText : colors.errorText} />
                <Text testID="approval-hash-status" style={[s.hashText, { color: req.hashVerified ? colors.successText : colors.errorText }]}>
                  {req.hashVerified ? "Hash recomputed locally from the payload - matches" : "HASH MISMATCH - payload may be spoofed. Approval blocked."}
                </Text>
              </View>
              {!meta?.tier2 ? (
                <Text testID="approval-no-tier2" style={s.warn}>
                  No Windows Hello key enrolled yet. Enroll it in Settings to approve with your fingerprint/face.
                </Text>
              ) : null}
              {err ? (
                <Text testID="approval-error" style={s.err}>
                  {err}
                </Text>
              ) : null}
              <View style={s.actions}>
                <Btn testID="approval-approve-hardware-btn" label="Approve with Windows Hello" icon="fingerprint" onPress={() => run("hardware")} loading={busy === "hardware"} disabled={!req.hashVerified || !meta?.tier2 || !!busy} style={{ flexGrow: 1 }} />
                <Btn testID="approval-deny-btn" label="Deny" variant="ghost" icon="close" onPress={() => run("deny")} loading={busy === "deny"} disabled={!!busy} />
              </View>
              {allowSimulatedUV ? (
                <Pressable testID="approval-simulated-btn" onPress={() => run("simulated")} disabled={!req.hashVerified || !!busy} style={s.simBtn}>
                  <Text style={s.simText}>{busy === "simulated" ? "Approving…" : "Test-only: approve with simulated verification (no biometric)"}</Text>
                </Pressable>
              ) : null}
            </ScrollView>
          </View>
        ) : null}
      </View>
    </Modal>
  );
}

const useStyles = makeStyles((c) => ({
  backdrop: { flex: 1, backgroundColor: c.overlay, justifyContent: "flex-end", alignItems: "center" },
  sheet: {
    width: "100%",
    maxWidth: 760,
    maxHeight: "92%",
    backgroundColor: c.surfaceSecondary,
    borderTopLeftRadius: radius.lg,
    borderTopRightRadius: radius.lg,
    borderWidth: 1,
    borderColor: c.brandPrimary,
    padding: spacing.xl,
  },
  top: { flexDirection: "row", gap: spacing.lg, alignItems: "flex-start" },
  img: { width: 72, height: 72, borderRadius: radius.md },
  title: { color: c.onSurface, fontSize: 22, fontWeight: "800", fontFamily: fonts.display },
  sub: { color: c.onSurfaceTertiary, fontSize: 13 },
  box: { backgroundColor: c.surface, borderRadius: radius.md, borderWidth: 1, borderColor: c.border, padding: spacing.lg, gap: spacing.md },
  row: { flexDirection: "row", gap: spacing.sm, alignItems: "center" },
  hashText: { fontSize: 12, fontWeight: "700", flex: 1 },
  warn: { color: c.warning, fontSize: 13 },
  err: { color: c.errorText, fontSize: 13, fontFamily: fonts.mono },
  actions: { flexDirection: "row", gap: spacing.md, flexWrap: "wrap" },
  simBtn: { paddingVertical: spacing.md, alignItems: "center" },
  simText: { color: c.muted, fontSize: 12, textDecorationLine: "underline" },
}));
