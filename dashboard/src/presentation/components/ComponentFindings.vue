<script setup lang="ts">
import { ExternalLink } from '@lucide/vue'
import { computed } from 'vue'
import type { Component, Finding, FindingFilter, TriageStatus } from '@/domain/models'
import { useFindings } from '@/presentation/composables/queries'
import { formatNumber } from '@/presentation/lib/format'
import SeverityBadge from './SeverityBadge.vue'
import TriageBadge from './TriageBadge.vue'
import { Button } from './ui/button'

const props = defineProps<{ component: Component, status: TriageStatus }>()
defineEmits<{ triage: [f: Finding] }>()

const pageSize = 200
const filter = computed<FindingFilter>(() => ({
  hostId: props.component.hostId,
  componentKind: props.component.kind,
  component: props.component.key,
  status: props.status,
  sort: 'severity',
  page: 1,
  pageSize,
}))
const findings = useFindings(filter)

const advisory = (cve: string) =>
  cve.startsWith('GHSA-') ? `https://github.com/advisories/${cve}` : `https://avd.aquasec.com/nvd/${cve.toLowerCase()}`
</script>

<template>
  <div>
    <p v-if="findings.isPending.value" class="py-3 text-sm text-muted-foreground">Loading findings…</p>
    <p v-else-if="findings.isError.value" class="py-3 text-sm text-destructive">{{ findings.error.value?.message }}</p>
    <ul v-else class="divide-y">
      <li v-for="f in findings.data.value?.items ?? []" :key="f.id" class="flex items-center gap-3 py-2 text-sm">
        <SeverityBadge :severity="f.severity" class="shrink-0" />
        <div class="min-w-0 flex-1">
          <a :href="advisory(f.cve)" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 font-mono text-xs hover:underline">
            {{ f.cve }} <ExternalLink class="size-3" />
          </a>
          <span class="ml-2 text-xs text-muted-foreground">{{ f.pkg }} {{ f.installedVersion }} → <span class="text-ok">{{ f.fixedVersion || 'no fix' }}</span></span>
          <p class="truncate text-xs text-muted-foreground" :title="f.title">{{ f.title }}</p>
        </div>
        <TriageBadge v-if="f.status !== 'open'" :status="f.status" class="shrink-0" />
        <Button size="sm" variant="ghost" class="shrink-0" @click="$emit('triage', f)">Triage</Button>
      </li>
    </ul>
    <p v-if="(findings.data.value?.total ?? 0) > pageSize" class="pt-2 text-xs text-muted-foreground">
      Showing {{ pageSize }} of {{ formatNumber(findings.data.value!.total) }}, most severe first.
    </p>
  </div>
</template>
