<script setup lang="ts">
import { computed } from 'vue'
import type { Severity } from '@/domain/models'

const props = defineProps<{ severity: Severity }>()
const cls = computed(() => ({
  CRITICAL: 'bg-sev-critical/12 text-sev-critical ring-sev-critical/30',
  HIGH: 'bg-sev-high/12 text-sev-high ring-sev-high/30',
  MEDIUM: 'bg-sev-medium/15 text-sev-medium ring-sev-medium/30',
  LOW: 'bg-sev-low/12 text-sev-low ring-sev-low/30',
  UNKNOWN: 'bg-sev-unknown/12 text-sev-unknown ring-sev-unknown/30',
})[props.severity])
</script>

<template>
  <span :class="['inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold tracking-wide ring-1 ring-inset', cls]">
    {{ severity }}
  </span>
</template>
