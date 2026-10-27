<script setup lang="ts">
import { VisAxis, VisCrosshair, VisLine, VisScatter, VisTooltip, VisXYContainer } from '@unovis/vue'
import type { TrendPoint } from '@/domain/models'
import { type ChartConfig, ChartContainer, ChartTooltipContent, componentToString } from '@/presentation/components/ui/chart'
import { formatDate } from '@/presentation/lib/format'

defineProps<{ points: TrendPoint[] }>()

const config = {
  critical: { label: 'Critical', color: 'var(--sev-critical)' },
  high: { label: 'High', color: 'var(--sev-high)' },
} satisfies ChartConfig

const x = (d: TrendPoint) => d.day.getTime()
const ys = [(d: TrendPoint) => d.critical, (d: TrendPoint) => d.high]
const colors = [config.critical.color, config.high.color]
const tickDate = (t: number | Date) => formatDate(new Date(t))
const tooltip = componentToString(config, ChartTooltipContent, { labelFormatter: tickDate })
</script>

<template>
  <div v-if="!points.length" class="flex h-56 items-center justify-center text-sm text-muted-foreground">
    No successful scans in this period.
  </div>
  <ChartContainer v-else :config="config" class="aspect-auto h-56">
    <VisXYContainer :data="points" :margin="{ left: 4, right: 12, top: 8 }" :y-domain="[0, undefined]">
      <VisLine :x="x" :y="ys" :color="colors" :line-width="2" />
      <VisScatter :x="x" :y="ys" :color="colors" :size="6" />
      <VisAxis type="x" :x="x" :tick-format="tickDate" :grid-line="false" :num-ticks="Math.min(points.length, 6)" />
      <VisAxis type="y" :num-ticks="4" :tick-line="false" :domain-line="false" />
      <VisTooltip />
      <VisCrosshair :x="x" :y="ys" :template="tooltip" :color="colors" />
    </VisXYContainer>
  </ChartContainer>
</template>
