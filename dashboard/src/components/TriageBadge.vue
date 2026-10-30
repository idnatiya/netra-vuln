<script setup lang="ts">
import type { TriageStatus } from '@/types/models'
import { Badge } from '@/components/ui/badge'

defineProps<{ status: TriageStatus }>()
const label: Record<TriageStatus, string> = { open: 'Open', accepted: 'Accepted', false_positive: 'False positive' }
</script>

<template>
  <Badge :variant="status === 'open' ? 'outline' : 'secondary'">{{ label[status] }}</Badge>
</template>
