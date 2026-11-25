import { QueryClientProvider } from "@tanstack/react-query";
import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useEffect } from "react";
import { LogBox, StyleSheet, Text, View } from "react-native";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import { KeyboardProvider } from "react-native-keyboard-controller";

import { agent, useAgent } from "@/src/agent/agent";
import { ApprovalSheet } from "@/src/components/ApprovalSheet";
import { ErrorBoundary } from "@/src/components/error-boundary";
import { queryClient } from "@/src/query-client";
import { colors, spacing, radius } from "@/src/theme";

LogBox.ignoreAllLogs(true);

function Toast() {
  const { toast } = useAgent();
  if (!toast) return null;
  const bg = toast.kind === "success" ? colors.success : toast.kind === "error" ? colors.error : colors.surfaceInverse;
  const fg = toast.kind === "info" ? colors.onSurfaceInverse : colors.onSuccess;
  return (
    <View pointerEvents="none" style={styles.toastWrap}>
      <View testID="app-toast" style={[styles.toast, { backgroundColor: bg }]}>
        <Text style={{ color: fg, fontSize: 13, fontWeight: "700" }}>{toast.msg}</Text>
      </View>
    </View>
  );
}

export default function RootLayout() {
  useEffect(() => {
    agent.init();
  }, []);
  return (
    <GestureHandlerRootView style={styles.root}>
      <ErrorBoundary>
        <QueryClientProvider client={queryClient}>
          <KeyboardProvider>
            <StatusBar style="light" />
            <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.surface } }} />
            <ApprovalSheet />
            <Toast />
          </KeyboardProvider>
        </QueryClientProvider>
      </ErrorBoundary>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.surface },
  toastWrap: { position: "absolute", left: 0, right: 0, bottom: spacing.xxl, alignItems: "center" },
  toast: { paddingHorizontal: spacing.lg, paddingVertical: spacing.md, borderRadius: radius.sm, maxWidth: 560 },
});
