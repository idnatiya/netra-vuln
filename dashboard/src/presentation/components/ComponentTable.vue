<script setup lang="ts">
import { Box, Cpu, Layers } from '@lucide/vue'
import type { Component, ComponentKind } from '@/domain/models'
import { componentLabel, daysSince } from '@/domain/rules'
import { Badge } from '@/presentation/components/ui/badge'
import { Button } from '@/presentation/components/ui/button'
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableRow } from '@/presentation/components/ui/table'

defineProps<{ rows: Component[], loading: boolean, error?: string }>()
defineEmits<{ select: [c: Component] }>()

const kinds: Record<ComponentKind, { label: string, icon: typeof Box }> = {
  os: { label: 'OS', icon: Layers },
  app: { label: 'App', icon: Box },
  binary: { label: 'Binary', icon: Cpu },
}
</script>

<template>
  <Table>
    <TableHeader>
      <TableRow>
        <TableHead>Component</TableHead>
        <TableHead>Packages</TableHead>
        <TableHead>Host</TableHead>
        <TableHead class="text-right">Critical</TableHead>
        <TableHead class="text-right">High</TableHead>
        <TableHead class="text-right">CVEs</TableHead>
        <TableHead class="text-right">Age</TableHead>
        <TableHead class="w-20" />
      </TableRow>
    </TableHeader>
    <TableBody :class="loading && 'opacity-60 transition-opacity'">
      <TableRow v-for="c in rows" :key="`${c.hostId}|${c.kind}|${c.key}`">
        <TableCell class="max-w-80">
          <div class="flex items-center gap-2">
            <Badge variant="outline" class="gap-1 text-[11px]"><component :is="kinds[c.kind].icon" class="size-3" /> {{ kinds[c.kind].label }}</Badge>
            <span class="truncate font-medium">{{ componentLabel(c).title }}</span>
          </div>
          <p class="mt-0.5 truncate font-mono text-xs text-muted-foreground" :title="c.key">
            {{ componentLabel(c).detail }}
            <span v-if="componentLabel(c).hint" class="font-sans text-sev-medium">· {{ componentLabel(c).hint }}</span>
          </p>
        </TableCell>
        <TableCell class="max-w-64">
          <p class="truncate text-xs text-muted-foreground" :title="c.packages.join('\n')">
            {{ c.packages.slice(0, 4).join(', ') }}<template v-if="c.pkgCount > 4"> +{{ c.pkgCount - 4 }}</template>
          </p>
        </TableCell>
        <TableCell class="text-sm">
          <div>{{ c.hostname }}</div>
          <div class="text-xs text-muted-foreground">{{ c.client }}</div>
        </TableCell>
        <TableCell class="text-right tabular-nums" :class="{ 'font-semibold text-sev-critical': c.critical > 0 }">{{ c.critical }}</TableCell>
        <TableCell class="text-right tabular-nums" :class="{ 'text-sev-high': c.high > 0 }">{{ c.high }}</TableCell>
        <TableCell class="text-right tabular-nums" :title="`${c.findings} findings`">{{ c.cves }}</TableCell>
        <TableCell class="text-right tabular-nums">{{ daysSince(c.firstSeen) }}d</TableCell>
        <TableCell><Button size="sm" variant="outline" @click="$emit('select', c)">View</Button></TableCell>
      </TableRow>
      <TableEmpty v-if="!loading && !error && !rows.length" :colspan="8">No findings match these filters.</TableEmpty>
      <TableEmpty v-if="error" :colspan="8"><span class="text-destructive">{{ error }}</span></TableEmpty>
    </TableBody>
  </Table>
</template>
