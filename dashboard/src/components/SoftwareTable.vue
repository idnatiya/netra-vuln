<script setup lang="ts">
import { computed } from 'vue'
import type { EOLStatus, Software } from '@/types/models'
import { eolLabel } from '@/lib/rules'

const props = defineProps<{ software: Software[] }>()

const order: Record<EOLStatus, number> = { eol: 0, soon: 1, supported: 2, unknown: 3 }
const rows = computed(() => [...props.software].sort((a, b) => order[a.status] - order[b.status] || a.name.localeCompare(b.name)))
const badge: Record<EOLStatus, string> = {
  eol: 'bg-sev-critical/15 text-sev-critical',
  soon: 'bg-sev-high/15 text-sev-high',
  supported: 'bg-muted text-muted-foreground',
  unknown: 'bg-muted text-muted-foreground',
}
const grid = 'grid grid-cols-[minmax(0,1fr)_7rem] items-center gap-x-4 md:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,1.4fr)_9rem]'
</script>

<template>
  <div class="overflow-hidden rounded-md border bg-card">
    <div :class="[grid, 'border-b bg-muted px-4 py-2.5 text-muted-foreground']">
      <span class="micro-cap">Software</span><span class="micro-cap hidden md:block">Latest in cycle</span>
      <span class="micro-cap hidden md:block">Path</span><span class="micro-cap text-right">End of life</span>
    </div>
    <p v-if="!rows.length" class="px-4 py-6 text-center text-muted-foreground">
      No software reported yet. Agents from v0.3.0 send it with each scan.
    </p>
    <div v-for="s in rows" :key="`${s.name}|${s.path}`" :class="[grid, 'border-b px-4 py-3 last:border-b-0']">
      <div class="min-w-0">
        <p class="truncate font-medium">{{ s.name }} <span class="font-mono text-[13px] text-muted-foreground">{{ s.version }}</span></p>
        <p v-if="s.cycle" class="text-[13px] text-muted-foreground">cycle {{ s.cycle }}</p>
      </div>
      <span class="hidden truncate font-mono text-[13px] text-muted-foreground md:block">{{ s.latest || '–' }}</span>
      <span class="hidden truncate font-mono text-[13px] text-muted-foreground md:block" :title="s.path">{{ s.path || '–' }}</span>
      <span class="justify-self-end rounded px-2 py-0.5 text-[13px] font-medium" :class="badge[s.status]">{{ eolLabel(s) }}</span>
    </div>
  </div>
</template>
