<script setup lang="ts">
import type { HostLevel } from '@/lib/rules'

// The 3px colour band on the left of a stream row (parent must be `relative`).
defineProps<{ level: HostLevel }>()
const color: Record<HostLevel, string> = {
  critical: 'bg-sev-critical', high: 'bg-sev-high', clean: 'bg-ok', none: 'bg-muted-foreground/30',
}
</script>

<template>
  <span aria-hidden="true" :class="['absolute inset-y-0 left-0 w-[3px]', color[level]]" />
</template>
