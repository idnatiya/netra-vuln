<script setup lang="ts">
import { ArrowDownWideNarrow, Users } from '@lucide/vue'
import { computed, ref } from 'vue'
import type { Host } from '@/types/models'
import { type HostTab, hostIssues, hostLevel, inHostTab, worstFirst } from '@/lib/rules'
import ClientChip from '@/components/ClientChip.vue'
import CountCell from '@/components/CountCell.vue'
import FilterBar from '@/components/FilterBar.vue'
import FilterSelect from '@/components/FilterSelect.vue'
import LevelStripe from '@/components/LevelStripe.vue'
import PageHeader from '@/components/PageHeader.vue'
import SearchBox from '@/components/SearchBox.vue'
import TrendSparkline from '@/components/TrendSparkline.vue'
import UnderlineTabs from '@/components/UnderlineTabs.vue'
import { useClients, useHosts } from '@/composables/queries'
import { useClientFilter } from '@/composables/useClientFilter'
import { relative } from '@/lib/format'

const ALL = '__all__'
const { client } = useClientFilter()
const hosts = useHosts(client)
const clients = useClients()
const search = ref('')
const tab = ref<HostTab>('attention')
type Sort = 'worst' | 'name' | 'scan'
const sort = ref<Sort>('worst')

const clientFilter = computed({
  get: () => client.value ?? ALL,
  set: (v: string) => (client.value = v === ALL ? undefined : v),
})
const clientOptions = computed(() => [
  { value: ALL, label: 'All clients' },
  ...(clients.data.value ?? []).map((c) => ({ value: c.name, label: c.name })),
])
const sortOptions: { value: Sort, label: string }[] = [
  { value: 'worst', label: 'Worst first' }, { value: 'name', label: 'Name' }, { value: 'scan', label: 'Last scan' },
]

const matching = computed(() => {
  const q = search.value.trim().toLowerCase()
  return (hosts.data.value ?? []).filter((h) => !q
    || [h.hostname, h.client, h.osName, h.osVersion, ...hostIssues(h)].some((s) => s.toLowerCase().includes(q)))
})

const tabs = computed(() => ([
  ['attention', 'Needs attention'], ['all', 'All'], ['stale', 'Not reporting'], ['revoked', 'Revoked'],
] as const).map(([value, label]) => ({ value, label, count: matching.value.filter((h) => inHostTab(h, value)).length })))

const bySort: Record<Sort, (a: Host, b: Host) => number> = {
  worst: worstFirst,
  name: (a, b) => a.hostname.localeCompare(b.hostname),
  scan: (a, b) => (b.lastScanAt?.getTime() ?? 0) - (a.lastScanAt?.getTime() ?? 0),
}
const rows = computed(() => matching.value.filter((h) => inHostTab(h, tab.value)).sort(bySort[sort.value]))
const tokens = computed(() => (client.value ? [{ key: 'client', value: client.value }] : []))

const os = (h: Host) => [h.osName && `${h.osName} ${h.osVersion}`.trim(), h.arch].filter(Boolean).join(' · ')
const grid = 'grid grid-cols-[minmax(0,1fr)_3.5rem_3.5rem] items-center gap-x-4 sm:grid-cols-[minmax(0,1fr)_9rem_5rem_5rem_8rem]'
</script>

<template>
  <PageHeader title="Hosts" description="Every enrolled VM, worst first." />

  <div class="flex flex-wrap items-center gap-2">
    <FilterBar>
      <FilterSelect v-model="clientFilter" :icon="Users" label="Client" :options="clientOptions" />
      <FilterSelect v-model="sort" :icon="ArrowDownWideNarrow" label="Sort" :options="sortOptions" />
    </FilterBar>
  </div>
  <SearchBox v-model="search" placeholder="Search hosts by name, OS, or issue…" :tokens="tokens" @remove-token="client = undefined" />

  <UnderlineTabs v-model="tab" :tabs="tabs" />

  <div class="overflow-hidden rounded-md border bg-card">
    <div :class="[grid, 'border-b bg-muted px-4 py-2.5 text-muted-foreground']">
      <span class="micro-cap">Host</span>
      <span class="micro-cap hidden sm:block">Graph · 14d</span>
      <span class="micro-cap text-right">Critical</span>
      <span class="micro-cap text-right">High</span>
      <span class="micro-cap hidden text-right sm:block">Last scan</span>
    </div>

    <p v-if="hosts.isPending.value" class="px-4 py-6 text-muted-foreground">Loading…</p>
    <p v-else-if="hosts.isError.value" class="px-4 py-6 text-destructive">{{ hosts.error.value?.message }}</p>
    <p v-else-if="!rows.length" class="px-4 py-6 text-center text-muted-foreground">
      {{ (hosts.data.value ?? []).length ? 'No hosts in this view.' : 'No hosts yet. Create a client, then add an agent to its VMs.' }}
    </p>

    <RouterLink
      v-for="h in rows"
      :key="h.id"
      :to="{ name: 'host', params: { id: h.id } }"
      :class="[grid, 'relative border-b px-4 py-3.5 last:border-b-0 hover:bg-muted/40', h.revokedAt && 'opacity-60']"
    >
      <LevelStripe :level="hostLevel(h)" />
      <div class="min-w-0">
        <p class="truncate font-semibold">{{ h.hostname }}</p>
        <p class="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-[13px] text-muted-foreground">
          <ClientChip :name="h.client" />
          <span>{{ os(h) }}</span>
          <span v-if="hostIssues(h).length" class="text-foreground">· {{ hostIssues(h).join(', ') }}</span>
        </p>
      </div>
      <div class="hidden sm:block"><TrendSparkline :host-id="h.id" :level="hostLevel(h)" /></div>
      <div class="text-right"><CountCell :value="h.lastOkScanAt ? h.openCritical : null" /></div>
      <div class="text-right"><CountCell :value="h.lastOkScanAt ? h.openHigh : null" /></div>
      <div class="hidden text-right text-[13px] text-muted-foreground sm:block">
        <span v-if="h.lastScanStatus === 'error'" class="inline-flex items-center gap-1.5"><span class="size-1.5 rounded-full bg-sev-critical" />failed</span>
        <span v-else-if="h.lastScanAt">{{ relative(h.lastScanAt) }}</span>
        <span v-else>enrolled {{ relative(h.createdAt) }}</span>
      </div>
    </RouterLink>
  </div>
</template>
