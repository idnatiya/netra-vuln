<script setup lang="ts">
import type { Component } from 'vue'
import { Card, CardContent } from '@/presentation/components/ui/card'
import { formatNumber } from '@/presentation/lib/format'

defineProps<{ label: string, value: number | undefined, hint?: string, tone?: 'critical' | 'high' | 'warn' | 'muted', icon?: Component }>()
</script>

<template>
  <Card class="gap-0 py-4">
    <CardContent class="px-4">
      <div class="flex items-center justify-between text-xs font-medium text-muted-foreground">
        {{ label }}
        <component :is="icon" v-if="icon" class="size-4" />
      </div>
      <div
        class="mt-1 text-3xl font-semibold tabular-nums"
        :class="{
          'text-sev-critical': tone === 'critical' && value,
          'text-sev-high': tone === 'high' && value,
          'text-sev-medium': tone === 'warn' && value,
        }"
      >
        <span v-if="value === undefined" class="inline-block h-8 w-16 animate-pulse rounded bg-muted" />
        <template v-else>{{ formatNumber(value) }}</template>
      </div>
      <p v-if="hint" class="mt-1 text-xs text-muted-foreground">{{ hint }}</p>
    </CardContent>
  </Card>
</template>
