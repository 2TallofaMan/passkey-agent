import { Redirect, Tabs } from "expo-router";
import { NativeTabs } from "expo-router/unstable-native-tabs";
import { Platform } from "react-native";

import { useAgent } from "@/src/agent/agent";
import { Icon, IconName } from "@/src/components/ui";
import { usesNativeTabs } from "@/src/navigation";
import { useTheme } from "@/src/theme";

const TABS: { name: string; title: string; icon: IconName; sf: string }[] = [
  { name: "vault", title: "Vault", icon: "safe-square-outline", sf: "lock.shield.fill" },
  { name: "chaos", title: "Chaos", icon: "lightning-bolt", sf: "bolt.fill" },
  { name: "audit", title: "Audit", icon: "format-list-checks", sf: "list.bullet.rectangle" },
  { name: "settings", title: "Settings", icon: "cog", sf: "gearshape.fill" },
];

export default function TabsLayout() {
  const { colors } = useTheme();
  const { status, approvals } = useAgent();
  if (status === "uninitialized") return <Redirect href="/onboarding" />;

  if (usesNativeTabs) {
    return (
      <NativeTabs>
        {TABS.map((t) => (
          <NativeTabs.Trigger key={t.name} name={t.name}>
            <NativeTabs.Trigger.Icon sf={t.sf as any} />
            <NativeTabs.Trigger.Label>{t.title}</NativeTabs.Trigger.Label>
          </NativeTabs.Trigger>
        ))}
      </NativeTabs>
    );
  }

  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarActiveTintColor: colors.brandPrimary,
        tabBarInactiveTintColor: colors.muted,
        tabBarStyle: { backgroundColor: colors.surfaceSecondary, borderTopColor: colors.border, ...(Platform.OS === "web" ? { height: 64 } : {}) },
        tabBarItemStyle: { alignSelf: "center" },
        tabBarLabelStyle: { fontSize: 11, fontWeight: "700", letterSpacing: 0.6 },
      }}
    >
      {TABS.map((t) => (
        <Tabs.Screen
          key={t.name}
          name={t.name}
          options={{
            title: t.title,
            tabBarButtonTestID: `tab-${t.name}`,
            tabBarIcon: ({ color }) => <Icon name={t.icon} size={22} color={String(color)} />,
            tabBarBadge: t.name === "vault" && approvals.length ? approvals.length : undefined,
          }}
        />
      ))}
    </Tabs>
  );
}
