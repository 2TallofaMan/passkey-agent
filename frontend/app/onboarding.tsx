import { BlurView } from "expo-blur";
import { useRouter } from "expo-router";
import { useEffect, useMemo, useState } from "react";
import { Platform, Pressable, ScrollView, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { agent } from "@/src/agent/agent";
import * as C from "@/src/agent/crypto";
import { Badge, Btn, Card, Field, Icon } from "@/src/components/ui";
import { fonts, makeStyles, radius, spacing, useTheme } from "@/src/theme";

type Step = "choose" | "reveal" | "confirm" | "restore";

// Web equivalent of FLAG_SECURE: secrets are blurred by default, only visible while held,
// re-blurred when the window loses focus or is hidden, and not selectable/copyable.
function useSecureWindow(onHide: () => void) {
  useEffect(() => {
    if (Platform.OS !== "web") return;
    const hide = () => onHide();
    const vis = () => document.visibilityState !== "visible" && onHide();
    window.addEventListener("blur", hide);
    document.addEventListener("visibilitychange", vis);
    return () => {
      window.removeEventListener("blur", hide);
      document.removeEventListener("visibilitychange", vis);
    };
  }, [onHide]);
}

export default function Onboarding() {
  const s = useStyles();
  const { colors } = useTheme();
  const insets = useSafeAreaInsets();
  const router = useRouter();
  const [step, setStep] = useState<Step>("choose");
  const [mnemonic, setMnemonic] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [restoreText, setRestoreText] = useState("");
  const [answers, setAnswers] = useState<[string, string]>(["", ""]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useSecureWindow(useMemo(() => () => setRevealed(false), []));

  const words = mnemonic ? mnemonic.split(" ") : [];
  const checkIdx = useMemo(() => {
    const a = Math.floor(Math.random() * 12);
    return [a, 12 + Math.floor(Math.random() * 12)] as [number, number];
  }, [mnemonic]); // eslint-disable-line react-hooks/exhaustive-deps

  const finish = async (phrase: string, mode: "new" | "restore") => {
    setBusy(true);
    setErr(null);
    try {
      const r = await agent.onboard(phrase, passphrase, mode);
      setMnemonic("");
      setRestoreText("");
      setPassphrase("");
      if (mode === "restore") agent.toast(r.backupFound ? `Restored ${r.restoredDomains} domain(s) from encrypted backup` : "Identity restored - no backup found", "success");
      router.replace("/(tabs)/vault");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <ScrollView style={s.root} contentContainerStyle={[s.content, { paddingTop: insets.top + spacing.xxl, paddingBottom: insets.bottom + spacing.xxl }]} keyboardShouldPersistTaps="handled">
      <View style={s.wrap}>
        <View style={s.brandRow}>
          <Icon name="shield-key" size={28} color={colors.brandPrimary} />
          <Text style={s.brand}>AEGIS CREDENTIAL AGENT</Text>
        </View>
        <Text style={s.lead}>
          Deterministic passkey & password agent. Your 24-word seed is the only way to recover this agent if this device is lost.
        </Text>

        {step === "choose" && (
          <View style={s.choose}>
            <Pressable testID="onboard-create-btn" style={({ hovered }: any) => [s.option, hovered && s.optionHover]} onPress={() => { setMnemonic(C.newMnemonic()); setStep("reveal"); }}>
              <Icon name="seed-plus" size={28} color={colors.brandPrimary} />
              <Text style={s.optTitle}>Create new identity</Text>
              <Text style={s.optSub}>Generate a 24-word BIP-39 seed (256-bit entropy)</Text>
            </Pressable>
            <Pressable testID="onboard-restore-btn" style={({ hovered }: any) => [s.option, hovered && s.optionHover]} onPress={() => setStep("restore")}>
              <Icon name="backup-restore" size={28} color={colors.brandPrimary} />
              <Text style={s.optTitle}>Restore from seed</Text>
              <Text style={s.optSub}>Replacement device: re-derive keys & pull encrypted backup</Text>
            </Pressable>
          </View>
        )}

        {step === "reveal" && (
          <Card title="Your recovery phrase" right={<Badge label="NO BACKUP, NO RECOVERY" kind="error" />}>
            <Text style={s.note}>Write these 24 words on paper or metal. They are never stored or sent anywhere. Hold the button to reveal.</Text>
            <View style={s.seedBox} testID="seed-grid">
              <View style={s.grid}>
                {words.map((w, i) => (
                  <View key={i} style={s.word}>
                    <Text style={s.wordIdx}>{String(i + 1).padStart(2, "0")}</Text>
                    <Text testID={`seed-word-${i + 1}`} style={s.wordText}>
                      {w}
                    </Text>
                  </View>
                ))}
              </View>
              {!revealed && (
                <BlurView testID="seed-blur-overlay" intensity={60} tint="dark" style={s.blur}>
                  <Icon name="eye-off" size={28} color={colors.onSurface} />
                  <Text style={s.blurText}>Hidden. Blurs automatically when you leave this window.</Text>
                </BlurView>
              )}
            </View>
            <Pressable testID="seed-hold-to-reveal-btn" onPressIn={() => setRevealed(true)} onPressOut={() => setRevealed(false)} style={s.hold}>
              <Icon name="gesture-tap-hold" color={colors.onBrandTertiary} />
              <Text style={s.holdText}>{revealed ? "Release to hide" : "Press and hold to reveal"}</Text>
            </Pressable>
            <Field testID="onboard-passphrase-input" label="Optional BIP-39 passphrase (25th word)" value={passphrase} onChangeText={setPassphrase} secureTextEntry placeholder="Leave empty for none" />
            <View style={s.row}>
              <Btn testID="reveal-back-btn" label="Back" variant="ghost" onPress={() => { setMnemonic(""); setStep("choose"); }} />
              <Btn testID="reveal-continue-btn" label="I wrote it down" icon="check" onPress={() => { setRevealed(false); setStep("confirm"); }} style={{ flexGrow: 1 }} />
            </View>
          </Card>
        )}

        {step === "confirm" && (
          <Card title="Confirm your backup">
            <Text style={s.note}>Type the requested words to prove the phrase was written down.</Text>
            <View style={s.row}>
              <Field testID="confirm-word-a-input" label={`Word #${checkIdx[0] + 1}`} value={answers[0]} onChangeText={(t) => setAnswers([t, answers[1]])} />
              <Field testID="confirm-word-b-input" label={`Word #${checkIdx[1] + 1}`} value={answers[1]} onChangeText={(t) => setAnswers([answers[0], t])} />
            </View>
            {err ? <Text testID="onboard-error" style={s.err}>{err}</Text> : null}
            <View style={s.row}>
              <Btn testID="confirm-back-btn" label="Show again" variant="ghost" onPress={() => setStep("reveal")} />
              <Btn
                testID="confirm-finish-btn"
                label="Create agent"
                icon="shield-lock"
                loading={busy}
                style={{ flexGrow: 1 }}
                onPress={() => {
                  if (answers[0].trim().toLowerCase() !== words[checkIdx[0]] || answers[1].trim().toLowerCase() !== words[checkIdx[1]]) {
                    setErr("Words don't match. Check your written copy.");
                    return;
                  }
                  finish(mnemonic, "new");
                }}
              />
            </View>
          </Card>
        )}

        {step === "restore" && (
          <Card title="Restore from 24-word seed">
            <Field
              testID="restore-mnemonic-input"
              label={`Recovery phrase (${C.wordCount(restoreText)}/24 words)`}
              value={restoreText}
              onChangeText={setRestoreText}
              multiline
              placeholder="word1 word2 word3 …"
              style={{ minHeight: 110, paddingTop: spacing.md, textAlignVertical: "top" }}
            />
            <Field testID="restore-passphrase-input" label="BIP-39 passphrase (if you set one)" value={passphrase} onChangeText={setPassphrase} secureTextEntry />
            {err ? <Text testID="onboard-error" style={s.err}>{err}</Text> : null}
            <View style={s.row}>
              <Btn testID="restore-back-btn" label="Back" variant="ghost" onPress={() => setStep("choose")} />
              <Btn testID="restore-submit-btn" label="Restore agent" icon="backup-restore" loading={busy} onPress={() => finish(restoreText, "restore")} style={{ flexGrow: 1 }} />
            </View>
          </Card>
        )}
      </View>
    </ScrollView>
  );
}

const useStyles = makeStyles((c) => ({
  root: { flex: 1, backgroundColor: c.surface },
  content: { paddingHorizontal: spacing.xl, alignItems: "center" },
  wrap: { width: "100%", maxWidth: 820, gap: spacing.xl },
  brandRow: { flexDirection: "row", alignItems: "center", gap: spacing.md },
  brand: { color: c.onSurface, fontSize: 28, fontWeight: "800", letterSpacing: 2, fontFamily: fonts.display },
  lead: { color: c.onSurfaceTertiary, fontSize: 15, lineHeight: 22 },
  choose: { flexDirection: "row", flexWrap: "wrap", gap: spacing.lg },
  option: { flex: 1, minWidth: 260, backgroundColor: c.surfaceSecondary, borderWidth: 1, borderColor: c.border, borderRadius: radius.md, padding: spacing.xl, gap: spacing.sm },
  optionHover: { borderColor: c.brandPrimary },
  optTitle: { color: c.onSurface, fontSize: 18, fontWeight: "800", fontFamily: fonts.display },
  optSub: { color: c.muted, fontSize: 13 },
  note: { color: c.onSurfaceTertiary, fontSize: 13, lineHeight: 19 },
  seedBox: { borderRadius: radius.md, overflow: "hidden", borderWidth: 1, borderColor: c.border, backgroundColor: c.surface, userSelect: "none" } as any,
  grid: { flexDirection: "row", flexWrap: "wrap", padding: spacing.md },
  word: { width: "25%", minWidth: 130, flexDirection: "row", gap: spacing.sm, paddingVertical: spacing.sm, paddingHorizontal: spacing.sm },
  wordIdx: { color: c.muted, fontFamily: fonts.mono, fontSize: 12, width: 20 },
  wordText: { color: c.onSurface, fontFamily: fonts.mono, fontSize: 15, fontWeight: "700" },
  blur: { position: "absolute", top: 0, left: 0, right: 0, bottom: 0, alignItems: "center", justifyContent: "center", gap: spacing.sm, backgroundColor: c.overlay },
  blurText: { color: c.onSurfaceSecondary, fontSize: 13 },
  hold: { minHeight: 48, borderRadius: radius.sm, backgroundColor: c.brandTertiary, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: spacing.sm, userSelect: "none" } as any,
  holdText: { color: c.onBrandTertiary, fontWeight: "800", letterSpacing: 0.8, textTransform: "uppercase", fontSize: 13 },
  row: { flexDirection: "row", gap: spacing.md, flexWrap: "wrap", alignItems: "flex-end" },
  err: { color: c.errorText, fontSize: 13 },
}));
