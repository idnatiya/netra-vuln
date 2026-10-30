<script setup lang="ts">
import { computed } from 'vue'
import type { HostLevel } from '@/lib/rules'
import { dailyTotals } from '@/lib/rules'
import { useTrend } from '@/composables/queries'
import Sparkline from './Sparkline.vue'

// Open critical + high per day for one host or client, last 14 days.
const props = withDefaults(defineProps<{ hostId?: number, client?: string, level: HostLevel, width?: number }>(), { width: 140 })
const DAYS = 14

const trend = useTrend(computed(() => ({ hostId: props.hostId, client: props.client, days: DAYS })))
const values = computed(() => dailyTotals(trend.data.value ?? [], DAYS))
const color: Record<HostLevel, string> = {
  critical: 'text-sev-critical/80', high: 'text-sev-high/80', clean: 'text-muted-foreground/40', none: 'text-muted-foreground/40',
}
</script>

<template>
  <span v-if="level === 'none'" class="text-[13px] text-muted-foreground">no data</span>
  <Sparkline v-else :values="values" :width="width" :class="color[level]" />
</template>
