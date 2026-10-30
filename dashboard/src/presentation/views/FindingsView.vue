<script setup lang="ts">
import { ArrowDownWideNarrow, ChevronLeft, ChevronRight, CircleCheck, Server, TriangleAlert, Users } from '@lucide/vue'
import { refDebounced } from '@vueuse/core'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { type Finding, type FindingFilter, type FindingSort, SEVERITIES, type Severity, TRIAGE_STATUSES, type TriageStatus } from '@/domain/models'
import { pageCount } from '@/domain/rules'
import FilterBar from '@/presentation/components/FilterBar.vue'
import FilterSelect from '@/presentation/components/FilterSelect.vue'
import FindingRow from '@/presentation/components/FindingRow.vue'
import PageHeader from '@/presentation/components/PageHeader.vue'
import SearchBox from '@/presentation/components/SearchBox.vue'
import TriageDialog from '@/presentation/components/TriageDialog.vue'
import { useClients, useFindings, useHosts } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { formatNumber } from '@/presentation/lib/format'

const ANY = '__any__'
const route = useRoute()
const { client } = useClientFilter()
const hosts = useHosts(client)
const clients = useClients()

const q = (k: string) => (typeof route.query[k] === 'string' ? (route.query[k] as string) : '')
const search = ref(q('q'))
const searchDebounced = refDebounced(search, 300)
const severity = ref<string>(q('severity') || ANY)
const status = ref<string>(q('status') || 'open')
const hostId = ref<string>(q('host_id') || ANY)
const sort = ref<FindingSort>('severity')
const includeResolved = ref(false)
const page = ref(1)
const pageSize = 50

const clientFilter = computed({
  get: () => client.value ?? ANY,
  set: (v: string) => (client.value = v === ANY ? undefined : v),
})

const filter = computed<FindingFilter>(() => ({
  client: client.value,
  hostId: hostId.value === ANY ? undefined : Number(hostId.value),
  severity: severity.value === ANY ? undefined : (severity.value as Severity),
  status: status.value === ANY ? undefined : (status.value as TriageStatus),
  query: searchDebounced.value,
  includeResolved: includeResolved.value,
  sort: sort.value,
  page: page.value,
  pageSize,
}))
// Any filter change goes back to the first page.
watch(() => [client.value, hostId.value, severity.value, status.value, searchDebounced.value, includeResolved.value, sort.value], () => (page.value = 1))
watch(client, () => (hostId.value = ANY))

const findings = useFindings(filter)
const data = computed(() => findings.data.value)
const pages = computed(() => (data.value ? pageCount(data.value) : 1))
const triaging = ref<Finding | null>(null)

const statusLabel: Record<TriageStatus, string> = { open: 'Open', accepted: 'Accepted', false_positive: 'False positive' }
const clientOptions = computed(() => [{ value: ANY, label: 'All clients' }, ...(clients.data.value ?? []).map((c) => ({ value: c.name, label: c.name }))])
const hostOptions = computed(() => [
  { value: ANY, label: 'All hosts' },
  ...(hosts.data.value ?? []).filter((h) => !h.revokedAt).map((h) => ({ value: String(h.id), label: `${h.client}/${h.hostname}` })),
])
const severityOptions = [{ value: ANY, label: 'Any severity' }, ...SEVERITIES.map((s) => ({ value: s, label: s.charAt(0) + s.slice(1).toLowerCase() }))]
const statusOptions = [{ value: ANY, label: 'Any status' }, ...TRIAGE_STATUSES.map((s) => ({ value: s, label: statusLabel[s] }))]
const sortOptions: { value: FindingSort, label: string }[] = [
  { value: 'severity', label: 'Most severe' }, { value: 'first_seen', label: 'Oldest first' }, { value: 'last_seen', label: 'Recently seen' },
]

const tokens = computed(() => {
  const t: { key: string, value: string }[] = []
  if (client.value) t.push({ key: 'client', value: client.value })
  if (severity.value !== ANY) t.push({ key: 'severity', value: severity.value.toLowerCase() })
  if (status.value !== ANY) t.push({ key: 'is', value: status.value })
  if (includeResolved.value) t.push({ key: 'include', value: 'resolved' })
  return t
})
function removeToken(key: string) {
  if (key === 'client') client.value = undefined
  if (key === 'severity') severity.value = ANY
  if (key === 'is') status.value = ANY
  if (key === 'include') includeResolved.value = false
}

const grid = 'grid grid-cols-[minmax(0,1fr)_4.5rem] items-center gap-x-4 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)_11rem_4.5rem]'
</script>

<template>
  <PageHeader title="Search CVEs" description="Findings across every host." />

  <div class="flex flex-wrap items-center gap-3">
    <FilterBar>
      <FilterSelect v-model="clientFilter" :icon="Users" label="Client" :options="clientOptions" />
      <FilterSelect v-model="hostId" :icon="Server" label="Host" :options="hostOptions" />
      <FilterSelect v-model="severity" :icon="TriangleAlert" label="Severity" :options="severityOptions" />
      <FilterSelect v-model="status" :icon="CircleCheck" label="Status" :options="statusOptions" />
      <FilterSelect v-model="sort" :icon="ArrowDownWideNarrow" label="Sort" :options="sortOptions" />
    </FilterBar>
    <label class="flex items-center gap-2 text-muted-foreground">
      <input v-model="includeResolved" type="checkbox" class="accent-primary"> Include resolved
    </label>
  </div>
  <SearchBox v-model="search" placeholder="Search by CVE or package…" :tokens="tokens" @remove-token="removeToken" />

  <div class="overflow-hidden rounded-md border bg-card" :class="findings.isFetching.value && 'opacity-70 transition-opacity'">
    <div :class="[grid, 'border-b bg-muted px-4 py-2.5 text-muted-foreground']">
      <span class="micro-cap">CVE</span><span class="micro-cap hidden md:block">Package</span>
      <span class="micro-cap hidden md:block">Installed → fixed</span><span class="micro-cap hidden md:block">Host</span>
      <span class="micro-cap text-right">Age</span>
    </div>
    <p v-if="findings.isError.value" class="px-4 py-6 text-destructive">{{ findings.error.value?.message }}</p>
    <p v-else-if="findings.isSuccess.value && !data?.items.length" class="px-4 py-6 text-center text-muted-foreground">No findings match these filters.</p>
    <FindingRow v-for="f in data?.items ?? []" :key="f.id" :finding="f" :grid="grid" show-host @triage="triaging = f" />
  </div>

  <div class="flex items-center justify-between text-muted-foreground">
    <span class="text-[13px]">{{ data ? `${formatNumber(data.total)} findings · page ${page} of ${pages}` : 'Loading…' }}</span>
    <div class="inline-flex divide-x divide-input rounded-md border border-input bg-muted/40">
      <button type="button" aria-label="Previous page" class="inline-flex size-8 items-center justify-center hover:bg-muted disabled:opacity-40" :disabled="page <= 1" @click="page--"><ChevronLeft class="size-4" /></button>
      <button type="button" aria-label="Next page" class="inline-flex size-8 items-center justify-center hover:bg-muted disabled:opacity-40" :disabled="page >= pages" @click="page++"><ChevronRight class="size-4" /></button>
    </div>
  </div>

  <TriageDialog :finding="triaging" @close="triaging = null" />
</template>
