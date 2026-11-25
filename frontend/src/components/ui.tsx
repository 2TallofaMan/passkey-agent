import { MaterialDesignIcons } from "@react-native-vector-icons/material-design-icons";
import React from "react";
import { ActivityIndicator, Pressable, Text, TextInput, TextInputProps, View, ViewStyle } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { fonts, makeStyles, radius, spacing, useTheme } from "@/src/theme";

export type IconName = React.ComponentProps<typeof MaterialDesignIcons>["name"];

export function Icon({ name, size = 18, color }: { name: IconName; size?: number; color?: string }) {
  const { colors } = useTheme();
  return <MaterialDesignIcons name={name} size={size} color={color ?? colors.onSurfaceSecondary} />;
}

type BtnProps = {
  label: string;
  onPress: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  icon?: IconName;
  loading?: boolean;
  disabled?: boolean;
  testID: string;
  compact?: boolean;
  style?: ViewStyle;
};

export function Btn({ label, onPress, variant = "primary", icon, loading, disabled, testID, compact, style }: BtnProps) {
  const s = useStyles();
  const { colors } = useTheme();
  const fg = variant === "primary" ? colors.onBrandPrimary : variant === "danger" ? colors.onError : colors.onSurface;
  return (
    <Pressable
      testID={testID}
      onPress={onPress}
      disabled={disabled || loading}
      style={({ pressed, hovered }: any) => [
        s.btn,
        compact && s.btnCompact,
        variant === "primary" && s.btnPrimary,
        variant === "secondary" && s.btnSecondary,
        variant === "ghost" && s.btnGhost,
        variant === "danger" && s.btnDanger,
        (pressed || hovered) && { opacity: 0.85 },
        pressed && { transform: [{ scale: 0.98 }] },
        (disabled || loading) && { opacity: 0.45 },
        style,
      ]}
    >
      {loading ? <ActivityIndicator size="small" color={fg} /> : icon ? <Icon name={icon} size={16} color={fg} /> : null}
      <Text style={[s.btnText, { color: fg }]} numberOfLines={1}>
        {label}
      </Text>
    </Pressable>
  );
}

export function Badge({ label, kind = "neutral", testID }: { label: string; kind?: "neutral" | "success" | "warning" | "error" | "brand"; testID?: string }) {
  const s = useStyles();
  const { colors } = useTheme();
  const map = {
    neutral: [colors.surfaceTertiary, colors.onSurfaceTertiary],
    success: [colors.success, colors.onSuccess],
    warning: [colors.warning, colors.onWarning],
    error: [colors.error, colors.onError],
    brand: [colors.brandTertiary, colors.onBrandTertiary],
  } as const;
  const [bg, fg] = map[kind];
  return (
    <View testID={testID} style={[s.badge, { backgroundColor: bg }]}>
      <Text style={[s.badgeText, { color: fg }]}>{label}</Text>
    </View>
  );
}

export function Card({ title, right, children, testID, danger }: { title?: string; right?: React.ReactNode; children: React.ReactNode; testID?: string; danger?: boolean }) {
  const s = useStyles();
  return (
    <View testID={testID} style={[s.card, danger && s.cardDanger]}>
      {title ? (
        <View style={s.cardHead}>
          <Text style={[s.cardTitle, danger && s.cardTitleDanger]}>{title}</Text>
          {right}
        </View>
      ) : null}
      {children}
    </View>
  );
}

export function KV({ k, v, mono, testID }: { k: string; v: string; mono?: boolean; testID?: string }) {
  const s = useStyles();
  return (
    <View style={s.kv}>
      <Text style={s.kvK}>{k}</Text>
      <Text testID={testID} style={[s.kvV, mono && s.mono]} selectable numberOfLines={2}>
        {v}
      </Text>
    </View>
  );
}

export function Field(props: TextInputProps & { label: string; testID: string }) {
  const s = useStyles();
  const { colors } = useTheme();
  return (
    <View style={s.field}>
      <Text style={s.fieldLabel}>{props.label}</Text>
      <TextInput placeholderTextColor={colors.muted} autoCapitalize="none" autoCorrect={false} {...props} style={[s.input, props.style]} />
    </View>
  );
}

export function ScreenHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  const s = useStyles();
  const insets = useSafeAreaInsets();
  return (
    <View style={[s.header, { paddingTop: insets.top + spacing.lg }]}>
      <View style={{ flex: 1 }}>
        <Text style={s.headerTitle}>{title}</Text>
        {subtitle ? <Text style={s.headerSub}>{subtitle}</Text> : null}
      </View>
      {right}
    </View>
  );
}

export const useStyles = makeStyles((c) => ({
  btn: {
    minHeight: 44,
    paddingHorizontal: spacing.lg,
    borderRadius: radius.sm,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: spacing.sm,
  },
  btnCompact: { minHeight: 36, paddingHorizontal: spacing.md },
  btnPrimary: { backgroundColor: c.brandPrimary },
  btnSecondary: { backgroundColor: c.surfaceTertiary, borderWidth: 1, borderColor: c.borderStrong },
  btnGhost: { backgroundColor: "transparent", borderWidth: 1, borderColor: c.border },
  btnDanger: { backgroundColor: c.error },
  btnText: { fontSize: 13, fontWeight: "700", letterSpacing: 0.6, textTransform: "uppercase" },
  badge: { paddingHorizontal: spacing.sm, paddingVertical: 3, borderRadius: radius.sm, alignSelf: "flex-start" },
  badgeText: { fontSize: 11, fontWeight: "800", letterSpacing: 0.8, fontFamily: fonts.mono },
  card: { backgroundColor: c.surfaceSecondary, borderWidth: 1, borderColor: c.border, borderRadius: radius.md, padding: spacing.lg, gap: spacing.md },
  cardDanger: { borderColor: c.error },
  cardHead: { flexDirection: "row", alignItems: "center", justifyContent: "space-between", gap: spacing.md },
  cardTitle: { color: c.onSurface, fontSize: 14, fontWeight: "800", letterSpacing: 1.2, textTransform: "uppercase", fontFamily: fonts.display },
  cardTitleDanger: { color: c.errorText },
  kv: { flexDirection: "row", gap: spacing.md, alignItems: "flex-start" },
  kvK: { color: c.muted, fontSize: 12, width: 130, textTransform: "uppercase", letterSpacing: 0.6, paddingTop: 1 },
  kvV: { color: c.onSurfaceSecondary, fontSize: 13, flex: 1 },
  mono: { fontFamily: fonts.mono, fontSize: 12 },
  field: { gap: spacing.xs, flex: 1, minWidth: 200 },
  fieldLabel: { color: c.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 0.8 },
  input: {
    minHeight: 44,
    backgroundColor: c.surfaceTertiary,
    borderWidth: 1,
    borderColor: c.border,
    borderRadius: radius.sm,
    paddingHorizontal: spacing.md,
    color: c.onSurface,
    fontSize: 14,
    fontFamily: fonts.mono,
  },
  header: {
    flexDirection: "row",
    alignItems: "flex-end",
    paddingHorizontal: spacing.xl,
    paddingBottom: spacing.lg,
    backgroundColor: c.surface,
    borderBottomWidth: 1,
    borderBottomColor: c.divider,
    gap: spacing.md,
  },
  headerTitle: { color: c.onSurface, fontSize: 26, fontWeight: "800", letterSpacing: 0.5, fontFamily: fonts.display },
  headerSub: { color: c.muted, fontSize: 12, marginTop: 2, fontFamily: fonts.mono },
}));
