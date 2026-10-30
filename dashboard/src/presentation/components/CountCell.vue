<script setup lang="ts">
import { formatNumber } from '@/presentation/lib/format'

// A count in a stream row: bold when there is something, a dash when zero.
defineProps<{ value: number | null }>()
</script>

<template>
  <span v-if="value === null" class="text-muted-foreground">…</span>
  <span v-else-if="value > 0" class="font-semibold tabular-nums">{{ formatNumber(value) }}</span>
  <span v-else class="text-muted-foreground">–</span>
</template>
