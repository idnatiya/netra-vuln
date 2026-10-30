<script setup lang="ts">
import { Plus, SlidersHorizontal } from '@lucide/vue'
import { computed, ref } from 'vue'
import type { Client } from '@/types/models'
import CreateClientDialog from '@/components/CreateClientDialog.vue'
import PageHeader from '@/components/PageHeader.vue'
import ScanConfigDialog from '@/components/ScanConfigDialog.vue'
import SearchBox from '@/components/SearchBox.vue'
import TrendSparkline from '@/components/TrendSparkline.vue'
import { Button } from '@/components/ui/button'
import { useClients } from '@/composables/queries'
import { formatDate, formatNumber, plural } from '@/lib/format'

const clients = useClients()
const creating = ref(false)
const editing = ref<Client | null>(null)
const search = ref('')
const visible = computed(() => {
  const q = search.value.trim().toLowerCase()
  return (clients.data.value ?? []).filter((c) => !q || c.name.includes(q))
})
const level = (c: Client) => (c.openCritical > 0 ? 'critical' : c.openHigh > 0 ? 'high' : 'clean')
</script>

<template>
  <PageHeader title="Clients" description="Each client has its own hosts, enroll token, and scan settings.">
    <Button @click="creating = true"><Plus /> Create client</Button>
  </PageHeader>
  <SearchBox v-model="search" placeholder="Filter clients…" />

  <p v-if="clients.isSuccess.value && !clients.data.value?.length" class="text-muted-foreground">
    No clients yet. Create one to get an enroll token.
  </p>

  <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
    <div v-for="c in visible" :key="c.name" class="flex flex-col rounded-md border bg-card">
      <div class="flex items-center gap-3 px-4 pt-4">
        <span class="flex size-8 shrink-0 items-center justify-center rounded-md bg-brand font-semibold">{{ c.name.charAt(0).toUpperCase() }}</span>
        <div class="min-w-0 flex-1">
          <RouterLink :to="{ name: 'hosts', query: { client: c.name } }" class="font-semibold hover:underline">{{ c.name }}</RouterLink>
          <p class="truncate text-[13px] text-muted-foreground">
            {{ plural(c.hosts, 'host') }} · {{ c.scanConfig ? 'custom scan config' : 'agent defaults' }} · since {{ formatDate(c.createdAt) }}
          </p>
        </div>
      </div>
      <div class="px-4 py-4"><TrendSparkline :client="c.name" :level="level(c)" :width="280" class="h-7 w-full" /></div>
      <div class="grid grid-cols-2 divide-x border-t">
        <div class="px-4 py-2">
          <p class="micro-cap text-muted-foreground">Critical</p>
          <p class="font-semibold tabular-nums">{{ c.openCritical ? formatNumber(c.openCritical) : '–' }}</p>
        </div>
        <div class="px-4 py-2">
          <p class="micro-cap text-muted-foreground">High</p>
          <p class="font-semibold tabular-nums">{{ c.openHigh ? formatNumber(c.openHigh) : '–' }}</p>
        </div>
      </div>
      <div class="flex gap-2 border-t px-4 py-3">
        <RouterLink :to="{ name: 'add-agent', query: { client: c.name } }" class="inline-flex items-center px-2 underline">Add agent</RouterLink>
        <Button variant="outline" @click="editing = c"><SlidersHorizontal /> Scan config</Button>
      </div>
    </div>
  </div>

  <CreateClientDialog v-model:open="creating" />
  <ScanConfigDialog :client="editing" @close="editing = null" />
</template>
