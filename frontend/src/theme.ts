// Design tokens (from /app/design_guidelines.json). Dark-first utility palette.
import { useMemo } from "react";
import { Appearance, Platform, StyleSheet, useColorScheme } from "react-native";

export type ColorScheme = "light" | "dark";

const dark = {
  surface: "#0A0A0A",
  onSurface: "#F5F5F5",
  surfaceSecondary: "#141414",
  onSurfaceSecondary: "#E0E0E0",
  surfaceTertiary: "#1F1F1F",
  onSurfaceTertiary: "#B3B3B3",
  surfaceInverse: "#EAEAEA",
  onSurfaceInverse: "#0A0A0A",
  muted: "#757575",

  brand: "#FF5722",
  onBrand: "#FFFFFF",
  brandPrimary: "#FF5722",
  onBrandPrimary: "#FFFFFF",
  brandSecondary: "#E64A19",
  onBrandSecondary: "#FFFFFF",
  brandTertiary: "#3E1B10",
  onBrandTertiary: "#FF8A65",

  success: "#2E7D32",
  onSuccess: "#FFFFFF",
  successText: "#66BB6A",
  warning: "#F57C00",
  onWarning: "#FFFFFF",
  error: "#D32F2F",
  onError: "#FFFFFF",
  errorText: "#EF5350",
  info: "#424242",
  onInfo: "#FFFFFF",

  border: "#2C2C2C",
  borderStrong: "#424242",
  divider: "#1F1F1F",
  overlay: "rgba(0,0,0,0.7)",
};

export type ThemeColors = typeof dark;

export const defaultScheme = "dark" satisfies ColorScheme;
export const themes: { light: ThemeColors; dark?: ThemeColors } = { light: dark, dark };

export const spacing = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32, xxxl: 48 };
export const radius = { sm: 4, md: 8, lg: 12, pill: 999 };
export const fonts = {
  mono: Platform.select({ web: "ui-monospace, 'Cascadia Code', Consolas, monospace", default: "monospace" }) as string,
  display: Platform.select({ web: "'Rajdhani', 'Segoe UI', system-ui, sans-serif", default: undefined }) as string | undefined,
};

export function setColorScheme(scheme: ColorScheme | null) {
  Appearance.setColorScheme?.(scheme ?? "unspecified");
}
setColorScheme?.(themes.dark ? null : defaultScheme);

export function useTheme(): { scheme: ColorScheme; colors: ThemeColors } {
  const system = useColorScheme();
  const scheme: ColorScheme = (system === "light" || system === "dark") && themes[system] ? system : defaultScheme;
  return { scheme, colors: themes[scheme] ?? dark };
}

export const colors = dark;

export function makeStyles<T extends StyleSheet.NamedStyles<T> | StyleSheet.NamedStyles<any>>(
  factory: (colors: ThemeColors) => T & StyleSheet.NamedStyles<any>,
): () => T {
  return function useStyles(): T {
    const { colors } = useTheme();
    return useMemo(() => StyleSheet.create(factory(colors)), [colors]);
  };
}
