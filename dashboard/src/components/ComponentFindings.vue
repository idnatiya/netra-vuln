<script setup lang="ts">
import { computed } from 'vue'
import type { Component, Finding, FindingFilter, TriageStatus } from '@/types/models'
import { useFindings } from '@/composables/queries'
import { advisoryUrl, formatNumber } from '@/lib/format'
import SeverityBadge from './SeverityBadge.vue'
import TriageBadge from './TriageBadge.vue'

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
</script>

<template>
  <div>
    <p v-if="findings.isPending.value" class="py-3 text-muted-foreground">Loading findings…</p>
    <p v-else-if="findings.isError.value" class="py-3 text-destructive">{{ findings.error.value?.message }}</p>
    <div v-else class="overflow-x-auto rounded-md border">
      <table class="w-full min-w-[560px] whitespace-nowrap">
        <thead class="micro-cap bg-muted text-left text-muted-foreground">
          <tr>
            <th class="px-3 py-1.5 font-semibold">CVE</th>
            <th class="px-3 py-1.5 font-semibold">Severity</th>
            <th class="px-3 py-1.5 font-semibold">Package</th>
            <th class="px-3 py-1.5 font-semibold">Fixed in</th>
            <th class="px-3 py-1.5" />
          </tr>
        </thead>
        <tbody class="divide-y">
          <tr v-for="f in findings.data.value?.items ?? []" :key="f.id">
            <td class="px-3 py-2">
              <a :href="advisoryUrl(f.cve)" target="_blank" rel="noopener noreferrer" class="font-mono text-[13px] text-link hover:underline">{{ f.cve }}</a>
              <p class="max-w-72 truncate text-[13px] text-muted-foreground" :title="f.title">{{ f.title }}</p>
            </td>
            <td class="px-3 py-2"><SeverityBadge :severity="f.severity" /></td>
            <td class="px-3 py-2">{{ f.pkg }} <span class="font-mono text-[13px] text-muted-foreground">{{ f.installedVersion }}</span></td>
            <td class="px-3 py-2 font-mono text-[13px]">{{ f.fixedVersion || 'no fix' }}</td>
            <td class="px-3 py-2 text-right">
              <TriageBadge v-if="f.status !== 'open'" :status="f.status" class="mr-2" />
              <button type="button" class="text-[13px] text-muted-foreground hover:text-foreground" @click="$emit('triage', f)">Triage</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="(findings.data.value?.total ?? 0) > pageSize" class="pt-2 text-[13px] text-muted-foreground">
      Showing {{ pageSize }} of {{ formatNumber(findings.data.value!.total) }}, most severe first.
    </p>
  </div>
</template>
