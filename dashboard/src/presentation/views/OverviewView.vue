<script setup lang="ts">
import { CircleAlert, RotateCcw, Server, ShieldAlert, ShieldX } from '@lucide/vue'
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import type { Count } from '@/domain/models'
import { daysSince, hostHealth, hostIssues } from '@/domain/rules'
import SeverityBadge from '@/presentation/components/SeverityBadge.vue'
import StatCard from '@/presentation/components/StatCard.vue'
import TrendChart from '@/presentation/components/TrendChart.vue'
import { Badge } from '@/presentation/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/presentation/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/presentation/components/ui/table'
import { useDistribution, useHosts, useOldestCVEs, useOverview, useTrend } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { plural, relative } from '@/presentation/lib/format'

const router = useRouter()
const { client } = useClientFilter()
const overview = useOverview(client)
const trend = useTrend(client, 30)
const oldest = useOldestCVEs(client, 10)
const hosts = useHosts(client)
const dist = useDistribution()

const totals = computed(() => overview.data.value?.totals)
const attention = computed(() =>
  (hosts.data.value ?? [])
    .filter((h) => !h.revokedAt && hostIssues(h).length)
    .sort((a, b) => Number(hostHealth(b) === 'stale') - Number(hostHealth(a) === 'stale') || b.openCritical - a.openCritical),
)

function share(list: Count[], n: number) {
  const total = list.reduce((s, c) => s + c.n, 0)
  return total ? Math.round((n / total) * 100) : 0
}

function openFindings(query: Record<string, string>) {
  router.push({ name: 'findings', query: { ...(client.value ? { client: client.value } : {}), ...query } })
}
</script>

<template>
  <div class="grid gap-4 md:gap-6">
    <div class="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <StatCard label="Open critical" :value="totals?.openCritical" tone="critical" :icon="ShieldX" />
      <StatCard label="Open high" :value="totals?.openHigh" tone="high" :icon="ShieldAlert" />
      <StatCard
        label="Active hosts" :value="totals?.hosts" :icon="Server"
        :hint="totals ? `${totals.staleHosts} stale · ${plural(totals.clients, 'client')}` : undefined"
      />
      <StatCard
        label="Need attention" :value="totals ? totals.rebootRequired + totals.autoUpdateOff : undefined" tone="warn"
        :icon="RotateCcw" :hint="totals ? `${totals.rebootRequired} reboot · ${totals.autoUpdateOff} auto-update off` : undefined"
      />
    </div>

    <div class="grid gap-4 lg:grid-cols-3">
      <Card class="lg:col-span-2">
        <CardHeader>
          <CardTitle>Findings trend</CardTitle>
          <CardDescription>Critical and high per day, last 30 days (last successful scan of each host).</CardDescription>
        </CardHeader>
        <CardContent>
          <TrendChart :points="trend.data.value ?? []" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Hosts needing attention</CardTitle>
          <CardDescription>Stale, failing, reboot pending, or auto-update off.</CardDescription>
        </CardHeader>
        <CardContent class="grid gap-2">
          <p v-if="hosts.isSuccess.value && !attention.length" class="flex items-center gap-2 text-sm text-muted-foreground">
            <span class="size-2 rounded-full bg-ok" /> All hosts are reporting normally.
          </p>
          <RouterLink
            v-for="h in attention.slice(0, 8)"
            :key="h.id"
            :to="{ name: 'hosts', query: { client: h.client } }"
            class="rounded-md border p-2 text-sm hover:bg-muted/50"
          >
            <div class="flex items-center justify-between gap-2">
              <span class="truncate font-medium">{{ h.client }}/{{ h.hostname }}</span>
              <span class="shrink-0 text-xs text-muted-foreground">{{ relative(h.lastHeartbeatAt) }}</span>
            </div>
            <div class="mt-1 flex flex-wrap gap-1">
              <Badge v-for="issue in hostIssues(h)" :key="issue" variant="outline" class="text-[11px]">
                <CircleAlert v-if="hostHealth(h) === 'stale'" class="size-3 text-sev-high" /> {{ issue }}
              </Badge>
            </div>
          </RouterLink>
        </CardContent>
      </Card>
    </div>

    <div class="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Open findings by client</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client</TableHead>
                <TableHead class="text-right">Hosts</TableHead>
                <TableHead class="text-right">Critical</TableHead>
                <TableHead class="text-right">High</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow
                v-for="c in overview.data.value?.clients ?? []"
                :key="c.name"
                class="cursor-pointer"
                @click="client = c.name"
              >
                <TableCell class="font-medium">{{ c.name }}</TableCell>
                <TableCell class="text-right tabular-nums">{{ c.hosts }}</TableCell>
                <TableCell class="text-right tabular-nums" :class="{ 'font-semibold text-sev-critical': c.openCritical > 0 }">{{ c.openCritical }}</TableCell>
                <TableCell class="text-right tabular-nums" :class="{ 'text-sev-high': c.openHigh > 0 }">{{ c.openHigh }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Oldest open CVEs</CardTitle>
          <CardDescription>By first seen, across all hosts in scope.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CVE</TableHead>
                <TableHead class="text-right">Hosts</TableHead>
                <TableHead class="text-right">Age</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="v in oldest.data.value ?? []" :key="v.cve" class="cursor-pointer" @click="openFindings({ q: v.cve })">
                <TableCell class="max-w-0">
                  <div class="flex items-center gap-2">
                    <SeverityBadge :severity="v.severity" />
                    <span class="font-mono text-xs">{{ v.cve }}</span>
                  </div>
                  <p class="mt-0.5 truncate text-xs text-muted-foreground">{{ v.title }}</p>
                </TableCell>
                <TableCell class="text-right tabular-nums">{{ v.hosts }}</TableCell>
                <TableCell class="text-right tabular-nums">{{ daysSince(v.firstSeen) }}d</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>Fleet</CardTitle>
        <CardDescription>Active hosts by OS, agent version, and Trivy version.</CardDescription>
      </CardHeader>
      <CardContent class="grid gap-6 md:grid-cols-3">
        <div v-for="[title, list] in ([['Operating system', dist.data.value?.os], ['Agent', dist.data.value?.agentVersions], ['Trivy', dist.data.value?.trivyVersions]] as const)" :key="title">
          <h3 class="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{{ title }}</h3>
          <ul class="grid gap-2 text-sm">
            <li v-for="c in list ?? []" :key="c.key">
              <div class="flex justify-between gap-2"><span class="truncate">{{ c.key || 'unknown' }}</span><span class="tabular-nums text-muted-foreground">{{ c.n }}</span></div>
              <div class="mt-1 h-1.5 rounded-full bg-muted"><div class="h-full rounded-full bg-primary/70" :style="{ width: `${share(list ?? [], c.n)}%` }" /></div>
            </li>
          </ul>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
