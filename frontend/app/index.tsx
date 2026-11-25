import { Redirect } from "expo-router";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";

import { useAgent } from "@/src/agent/agent";
import { colors, spacing } from "@/src/theme";

export default function Index() {
  const { status } = useAgent();
  if (status === "ready") return <Redirect href="/(tabs)/vault" />;
  if (status === "uninitialized") return <Redirect href="/onboarding" />;
  return (
    <View style={styles.c} testID="boot-screen">
      {status === "unsupported" ? (
        <Text style={styles.t}>This agent runs in a desktop or mobile web browser (needs WebCrypto + IndexedDB). Open the web preview.</Text>
      ) : (
        <ActivityIndicator color={colors.brandPrimary} />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  c: { flex: 1, backgroundColor: colors.surface, alignItems: "center", justifyContent: "center", padding: spacing.xl },
  t: { color: colors.onSurface, textAlign: "center", fontSize: 15 },
});
