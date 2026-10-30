<script setup lang="ts">
import { computed } from 'vue'
import type { Severity } from '@/domain/models'

const props = defineProps<{ severity: Severity }>()
const cls = computed(() => ({
  CRITICAL: 'bg-sev-critical text-white',
  HIGH: 'bg-sev-high text-ink',
  MEDIUM: 'bg-sev-medium text-ink',
  LOW: 'bg-sev-low text-ink',
  UNKNOWN: 'bg-sev-unknown text-ink',
})[props.severity])
</script>

<template>
  <span :class="['micro-cap inline-flex items-center rounded-[4px] px-1.5', cls]">{{ severity }}</span>
</template>
