<script setup lang="ts">
import type { Host } from '@/domain/models'
import { type HostHealth, hostHealth } from '@/domain/rules'
import { formatNumber, relative } from '@/presentation/lib/format'

defineProps<{ host: Host, issues: string[] }>()

const dot: Record<HostHealth, string> = {
  healthy: 'bg-ok', attention: 'bg-sev-medium', stale: 'bg-sev-critical', revoked: 'bg-muted-foreground/40',
}
</script>

<template>
  <RouterLink
    :to="{ name: 'host', params: { id: host.id } }"
    class="group grid gap-3 rounded-lg border bg-background p-4 transition-colors hover:border-foreground/25"
    :class="host.revokedAt && 'opacity-60'"
  >
    <div class="flex items-start justify-between gap-3">
      <div class="min-w-0">
        <div class="flex items-center gap-2">
          <span :class="['size-2 shrink-0 rounded-full', dot[hostHealth(host)]]" :title="hostHealth(host)" />
          <span class="truncate font-medium group-hover:underline">{{ host.hostname }}</span>
        </div>
        <p class="mt-0.5 truncate text-xs text-muted-foreground">{{ host.osName }} {{ host.osVersion }} · {{ host.arch }}</p>
      </div>
      <span class="shrink-0 text-xs text-muted-foreground" :title="`last scan ${host.lastScanStatus || 'never'}`">
        {{ host.lastScanStatus === 'error' ? 'scan failed' : `scanned ${relative(host.lastScanAt)}` }}
      </span>
    </div>

    <p v-if="host.openCritical || host.openHigh" class="flex items-baseline gap-4 tabular-nums">
      <span><span class="text-2xl font-semibold" :class="host.openCritical ? 'text-sev-critical' : 'text-muted-foreground'">{{ formatNumber(host.openCritical) }}</span> <span class="text-xs text-muted-foreground">critical</span></span>
      <span><span class="text-2xl font-semibold" :class="host.openHigh ? 'text-foreground' : 'text-muted-foreground'">{{ formatNumber(host.openHigh) }}</span> <span class="text-xs text-muted-foreground">high</span></span>
    </p>
    <p v-else class="text-sm text-ok">No open critical or high findings</p>

    <p v-if="issues.length" class="text-xs text-sev-high">{{ issues.join(' · ') }}</p>
  </RouterLink>
</template>
