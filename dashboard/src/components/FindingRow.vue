<script setup lang="ts">
import type { Finding } from '@/types/models'
import { daysSince } from '@/lib/rules'
import { advisoryUrl, formatDateTime } from '@/lib/format'
import ClientChip from './ClientChip.vue'
import LevelStripe from './LevelStripe.vue'
import SeverityBadge from './SeverityBadge.vue'
import TriageBadge from './TriageBadge.vue'

// One finding in a stream: CVE + title, package, versions, host, age, triage.
defineProps<{ finding: Finding, grid: string, showHost?: boolean }>()
defineEmits<{ triage: [f: Finding] }>()
</script>

<template>
  <div :class="[grid, 'relative border-b px-4 py-3.5 last:border-b-0 hover:bg-muted/40']">
    <LevelStripe :level="finding.severity === 'CRITICAL' ? 'critical' : finding.severity === 'HIGH' ? 'high' : 'none'" />
    <div class="min-w-0">
      <p class="flex items-center gap-2">
        <a :href="advisoryUrl(finding.cve)" target="_blank" rel="noopener noreferrer" class="truncate font-mono font-semibold hover:text-link hover:underline">{{ finding.cve }}</a>
        <SeverityBadge :severity="finding.severity" />
        <TriageBadge v-if="finding.status !== 'open'" :status="finding.status" />
      </p>
      <p class="mt-0.5 truncate text-[13px] text-muted-foreground" :title="finding.title">{{ finding.title }}</p>
    </div>
    <div class="hidden min-w-0 md:block">
      <p class="truncate" :title="finding.pkgPath || finding.target">{{ finding.pkg }}</p>
      <p v-if="finding.note" class="truncate text-[13px] text-muted-foreground" :title="finding.note">{{ finding.note }}</p>
    </div>
    <div class="hidden min-w-0 font-mono text-[13px] md:block">
      <p class="truncate">{{ finding.installedVersion }}</p>
      <p class="truncate text-muted-foreground">→ {{ finding.fixedVersion || 'no fix' }}</p>
    </div>
    <div v-if="showHost" class="hidden min-w-0 md:block">
      <RouterLink :to="{ name: 'host', params: { id: finding.hostId } }" class="block truncate hover:text-link hover:underline">{{ finding.hostname }}</RouterLink>
      <div class="mt-0.5"><ClientChip :name="finding.client" /></div>
    </div>
    <div class="text-right text-[13px] text-muted-foreground">
      <span :title="`first seen ${formatDateTime(finding.firstSeen)}`">{{ finding.resolvedAt ? 'resolved' : `${daysSince(finding.firstSeen)}d` }}</span><br>
      <button type="button" class="mt-0.5 hover:text-foreground" @click="$emit('triage', finding)">Triage</button>
    </div>
  </div>
</template>
