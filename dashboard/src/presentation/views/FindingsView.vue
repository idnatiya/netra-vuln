<script setup lang="ts">
import { ChevronLeft, ChevronRight, ExternalLink, Search, X } from '@lucide/vue'
import { refDebounced } from '@vueuse/core'
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { type Component, type ComponentFilter, type Finding, type FindingFilter, type FindingSort, SEVERITIES, type Severity, TRIAGE_STATUSES, type TriageStatus } from '@/domain/models'
import { componentLabel, daysSince, pageCount } from '@/domain/rules'
import ComponentTable from '@/presentation/components/ComponentTable.vue'
import SeverityBadge from '@/presentation/components/SeverityBadge.vue'
import TriageBadge from '@/presentation/components/TriageBadge.vue'
import TriageDialog from '@/presentation/components/TriageDialog.vue'
import { Button } from '@/presentation/components/ui/button'
import { Card, CardContent } from '@/presentation/components/ui/card'
import { Input } from '@/presentation/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/presentation/components/ui/select'
import { Tabs, TabsList, TabsTrigger } from '@/presentation/components/ui/tabs'
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableRow } from '@/presentation/components/ui/table'
import { useComponents, useFindings, useHosts } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { formatDateTime, plural } from '@/presentation/lib/format'

const ANY = '__any__'
const route = useRoute()
const { client } = useClientFilter()
const hosts = useHosts(client)

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
// "components" groups findings into upgrade actions; "findings" is the flat list.
const view = ref<'components' | 'findings'>(q('view') === 'findings' || q('q') ? 'findings' : 'components')
const selected = ref<Component | null>(null)

const baseFilter = computed<ComponentFilter>(() => ({
  client: client.value,
  hostId: hostId.value === ANY ? undefined : Number(hostId.value),
  severity: severity.value === ANY ? undefined : (severity.value as Severity),
  status: status.value === ANY ? undefined : (status.value as TriageStatus),
  query: searchDebounced.value,
  includeResolved: includeResolved.value,
}))
const filter = computed<FindingFilter>(() => ({
  ...baseFilter.value,
  componentKind: selected.value?.kind,
  component: selected.value?.key,
  sort: sort.value,
  page: page.value,
  pageSize,
}))
// Any filter change goes back to the first page.
watch(() => [baseFilter.value, selected.value, sort.value], () => (page.value = 1))
watch(client, () => {
  hostId.value = ANY
  selected.value = null
})

const components = useComponents(baseFilter)
function openComponent(c: Component) {
  selected.value = c
  hostId.value = String(c.hostId)
  view.value = 'findings'
}

const findings = useFindings(filter)
const data = computed(() => findings.data.value)
const pages = computed(() => (data.value ? pageCount(data.value) : 1))
const triaging = ref<Finding | null>(null)

const statusLabel: Record<TriageStatus, string> = { open: 'Open', accepted: 'Accepted', false_positive: 'False positive' }
const advisory = (cve: string) =>
  cve.startsWith('GHSA-') ? `https://github.com/advisories/${cve}` : `https://avd.aquasec.com/nvd/${cve.toLowerCase()}`
</script>

<template>
  <div class="grid gap-4">
    <Tabs v-model="view">
      <TabsList>
        <TabsTrigger value="components">Components</TabsTrigger>
        <TabsTrigger value="findings">All findings</TabsTrigger>
      </TabsList>
    </Tabs>
    <Card class="py-3">
      <CardContent class="flex flex-wrap items-center gap-2 px-3">
        <div class="relative min-w-56 flex-1">
          <Search class="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input v-model="search" class="pl-8" placeholder="Search CVE or package" aria-label="Search CVE or package" />
        </div>
        <Select v-model="severity">
          <SelectTrigger class="w-36" aria-label="Severity"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem :value="ANY">Any severity</SelectItem>
            <SelectItem v-for="s in SEVERITIES" :key="s" :value="s">{{ s }}</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="status">
          <SelectTrigger class="w-40" aria-label="Status"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem :value="ANY">Any status</SelectItem>
            <SelectItem v-for="s in TRIAGE_STATUSES" :key="s" :value="s">{{ statusLabel[s] }}</SelectItem>
          </SelectContent>
        </Select>
        <Select v-model="hostId">
          <SelectTrigger class="w-44" aria-label="Host"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem :value="ANY">All hosts</SelectItem>
            <SelectItem v-for="h in (hosts.data.value ?? []).filter((h) => !h.revokedAt)" :key="h.id" :value="String(h.id)">
              {{ h.client }}/{{ h.hostname }}
            </SelectItem>
          </SelectContent>
        </Select>
        <Select v-if="view === 'findings'" v-model="sort">
          <SelectTrigger class="w-40" aria-label="Sort"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="severity">Most severe</SelectItem>
            <SelectItem value="first_seen">Oldest first</SelectItem>
            <SelectItem value="last_seen">Recently seen</SelectItem>
          </SelectContent>
        </Select>
        <label class="flex items-center gap-2 text-sm text-muted-foreground">
          <input v-model="includeResolved" type="checkbox" class="accent-primary"> Include resolved
        </label>
      </CardContent>
    </Card>

    <Card v-if="view === 'components'" class="py-0">
      <ComponentTable
        :rows="components.data.value ?? []" :loading="components.isFetching.value"
        :error="components.error.value?.message" @select="openComponent"
      />
    </Card>
    <template v-else>
    <div v-if="selected" class="flex items-center gap-2 text-sm">
      <span class="text-muted-foreground">Component:</span>
      <span class="font-medium">{{ componentLabel(selected).title }}</span>
      <span class="truncate font-mono text-xs text-muted-foreground">{{ selected.hostname }} · {{ componentLabel(selected).detail }}</span>
      <Button size="icon-sm" variant="ghost" aria-label="Clear component filter" @click="selected = null"><X /></Button>
    </div>

    <Card class="py-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead class="w-24">Severity</TableHead>
            <TableHead>Vulnerability</TableHead>
            <TableHead>Package</TableHead>
            <TableHead>Host</TableHead>
            <TableHead class="text-right">Age</TableHead>
            <TableHead>Status</TableHead>
            <TableHead class="w-20" />
          </TableRow>
        </TableHeader>
        <TableBody :class="findings.isFetching.value && 'opacity-60 transition-opacity'">
          <TableRow v-for="f in data?.items ?? []" :key="f.id">
            <TableCell><SeverityBadge :severity="f.severity" /></TableCell>
            <TableCell class="max-w-80">
              <a :href="advisory(f.cve)" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 font-mono text-xs hover:underline">
                {{ f.cve }} <ExternalLink class="size-3" />
              </a>
              <p class="truncate text-xs text-muted-foreground" :title="f.title">{{ f.title }}</p>
            </TableCell>
            <TableCell class="max-w-64">
              <div class="truncate font-medium" :title="f.pkg">{{ f.pkg }}</div>
              <div class="truncate text-xs text-muted-foreground" :title="`${f.pkgPath || f.target} (${f.type})`">
                {{ f.installedVersion }} → <span class="text-ok">{{ f.fixedVersion || 'no fix' }}</span>
              </div>
            </TableCell>
            <TableCell class="text-sm">
              <div>{{ f.hostname }}</div>
              <div class="text-xs text-muted-foreground">{{ f.client }}</div>
            </TableCell>
            <TableCell class="text-right tabular-nums" :title="`first seen ${formatDateTime(f.firstSeen)}`">
              {{ daysSince(f.firstSeen) }}d
            </TableCell>
            <TableCell>
              <TriageBadge :status="f.status" />
              <p v-if="f.resolvedAt" class="mt-1 text-xs text-ok">resolved</p>
              <p v-else-if="f.note" class="mt-1 max-w-40 truncate text-xs text-muted-foreground" :title="f.note">{{ f.note }}</p>
            </TableCell>
            <TableCell><Button size="sm" variant="outline" @click="triaging = f">Triage</Button></TableCell>
          </TableRow>
          <TableEmpty v-if="findings.isSuccess.value && !data?.items.length" :colspan="7">
            No findings match these filters.
          </TableEmpty>
          <TableEmpty v-if="findings.isError.value" :colspan="7">
            <span class="text-destructive">{{ findings.error.value?.message }}</span>
          </TableEmpty>
        </TableBody>
      </Table>
      <div class="flex items-center justify-between border-t px-4 py-3 text-sm text-muted-foreground">
        <span>{{ data ? plural(data.total, 'finding') : 'Loading…' }}</span>
        <div class="flex items-center gap-2">
          <span>Page {{ page }} of {{ pages }}</span>
          <Button size="icon-sm" variant="outline" aria-label="Previous page" :disabled="page <= 1" @click="page--"><ChevronLeft /></Button>
          <Button size="icon-sm" variant="outline" aria-label="Next page" :disabled="page >= pages" @click="page++"><ChevronRight /></Button>
        </div>
      </div>
    </Card>
    </template>

    <TriageDialog :finding="triaging" @close="triaging = null" />
  </div>
</template>
