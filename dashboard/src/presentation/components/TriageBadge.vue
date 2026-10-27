<script setup lang="ts">
import type { TriageStatus } from '@/domain/models'
import { Badge } from '@/presentation/components/ui/badge'

defineProps<{ status: TriageStatus }>()
const label: Record<TriageStatus, string> = { open: 'Open', accepted: 'Accepted', false_positive: 'False positive' }
</script>

<template>
  <Badge :variant="status === 'open' ? 'outline' : 'secondary'">{{ label[status] }}</Badge>
</template>
