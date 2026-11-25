import { useState } from "react";
import { FlatList, Pressable, ScrollView, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";

import { AuditEvent, useAgent } from "@/src/agent/agent";
import { Badge, Icon, ScreenHeader } from "@/src/components/ui";
import { usesNativeTabs } from "@/src/navigation";
import { fonts, makeStyles, radius, spacing } from "@/src/theme";

const FILTERS = ["all", "tier1", "tier2", "success", "warning", "error"] as const;
type Filter = (typeof FILTERS)[number];

const match = (e: AuditEvent, f: Filter) =>
  f === "all" ? true : f === "tier1" ? e.tier === 1 : f === "tier2" ? e.tier === 2 : e.severity === f;

function Row({ e, alt }: { e: AuditEvent; alt: boolean }) {
  const s = useStyles();
  const [open, setOpen] = useState(false);
  return (
    <Pressable testID={`audit-row-${e.id}`} onPress={() => setOpen(!open)} style={[s.row, alt && s.rowAlt]}>
      <View style={s.line}>
        <Text style={s.ts}>{new Date(e.ts).toLocaleString()}</Text>
        <Badge label={e.severity.toUpperCase()} kind={e.severity === "info" ? "neutral" : e.severity} />
        <Badge label={`T${e.tier}`} kind={e.tier === 2 ? "brand" : "neutral"} />
        <Text style={s.type}>{e.type}</Text>
        <Text style={s.domain}>{e.domain ?? ""}</Text>
      </View>
      <Text style={s.detail} numberOfLines={open ? undefined : 1}>
        {e.detail}
      </Text>
      {open ? (
        <View style={{ gap: 2 }}>
          <Text style={s.meta}>actor: {e.actor}</Text>
          {e.payloadSha256 ? <Text style={s.meta}>payload sha256: {e.payloadSha256}</Text> : null}
        </View>
      ) : null}
    </Pressable>
  );
}

export default function Audit() {
  const s = useStyles();
  const insets = useSafeAreaInsets();
  const { audit } = useAgent();
  const [filter, setFilter] = useState<Filter>("all");
  const data = audit.filter((e) => match(e, filter));
  const bottomChrome = usesNativeTabs ? insets.bottom : 0;

  return (
    <View style={s.root}>
      <ScreenHeader title="Audit Ledger" subtitle={`${audit.length} events · stored locally in the agent's encrypted store`} />
      <View style={s.filterBar}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={s.chips}>
          {FILTERS.map((f) => (
            <Pressable key={f} testID={`audit-filter-${f}`} onPress={() => setFilter(f)} style={[s.chip, filter === f && s.chipOn]}>
              <Text style={[s.chipText, filter === f && s.chipTextOn]}>{f.toUpperCase()}</Text>
            </Pressable>
          ))}
        </ScrollView>
      </View>
      <FlatList
        testID="audit-list"
        data={data}
        keyExtractor={(e) => e.id}
        renderItem={({ item, index }) => <Row e={item} alt={index % 2 === 1} />}
        contentContainerStyle={[s.list, { paddingBottom: bottomChrome + spacing.xl }]}
        ListEmptyComponent={
          <View style={s.empty} testID="audit-empty">
            <Icon name="text-box-search-outline" size={36} />
            <Text style={s.emptyText}>No audit events logged yet.</Text>
          </View>
        }
      />
    </View>
  );
}

const useStyles = makeStyles((c) => ({
  root: { flex: 1, backgroundColor: c.surface },
  filterBar: { height: 56, borderBottomWidth: 1, borderBottomColor: c.divider, backgroundColor: c.surface },
  chips: { gap: spacing.sm, paddingHorizontal: spacing.xl, alignItems: "center", height: 56 },
  chip: { height: 36, flexShrink: 0, paddingHorizontal: spacing.md, borderRadius: radius.pill, borderWidth: 1, borderColor: c.border, backgroundColor: c.surfaceTertiary, justifyContent: "center" },
  chipOn: { borderColor: c.brandPrimary, backgroundColor: c.brandTertiary },
  chipText: { color: c.onSurfaceTertiary, fontSize: 12, fontWeight: "700", letterSpacing: 0.6 },
  chipTextOn: { color: c.onBrandTertiary },
  list: { width: "100%", maxWidth: 1200, alignSelf: "center", paddingTop: spacing.md, paddingHorizontal: spacing.xl },
  row: { paddingVertical: spacing.md, paddingHorizontal: spacing.md, gap: spacing.xs, backgroundColor: c.surface, borderBottomWidth: 1, borderBottomColor: c.divider },
  rowAlt: { backgroundColor: c.surfaceSecondary },
  line: { flexDirection: "row", alignItems: "center", gap: spacing.sm, flexWrap: "wrap" },
  ts: { color: c.muted, fontFamily: fonts.mono, fontSize: 12, minWidth: 160 },
  type: { color: c.onSurface, fontFamily: fonts.mono, fontSize: 13, fontWeight: "700" },
  domain: { color: c.brandPrimary, fontFamily: fonts.mono, fontSize: 12 },
  detail: { color: c.onSurfaceTertiary, fontSize: 13 },
  meta: { color: c.muted, fontSize: 11, fontFamily: fonts.mono },
  empty: { alignItems: "center", padding: spacing.xxxl, gap: spacing.md },
  emptyText: { color: c.muted, fontSize: 14 },
}));
