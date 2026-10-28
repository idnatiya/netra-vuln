<script setup lang="ts">
import { Plus } from '@lucide/vue'
import { ref } from 'vue'
import type { Client } from '@/domain/models'
import CreateClientDialog from '@/presentation/components/CreateClientDialog.vue'
import ScanConfigDialog from '@/presentation/components/ScanConfigDialog.vue'
import { Button } from '@/presentation/components/ui/button'
import { Card } from '@/presentation/components/ui/card'
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableRow } from '@/presentation/components/ui/table'
import { useClients } from '@/presentation/composables/queries'
import { formatDate, plural } from '@/presentation/lib/format'

const clients = useClients()
const creating = ref(false)
const editing = ref<Client | null>(null)
</script>

<template>
  <div class="grid gap-4">
    <div class="flex items-center justify-between">
      <p class="text-sm text-muted-foreground">{{ plural(clients.data.value?.length ?? 0, 'client') }}</p>
      <Button @click="creating = true"><Plus /> New client</Button>
    </div>
    <Card class="py-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Client</TableHead>
            <TableHead class="text-right">Active hosts</TableHead>
            <TableHead class="text-right">Open critical</TableHead>
            <TableHead class="text-right">Open high</TableHead>
            <TableHead>Scan config</TableHead>
            <TableHead>Created</TableHead>
            <TableHead class="w-28" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="c in clients.data.value ?? []" :key="c.name">
            <TableCell>
              <RouterLink :to="{ name: 'hosts', query: { client: c.name } }" class="font-medium hover:underline">{{ c.name }}</RouterLink>
            </TableCell>
            <TableCell class="text-right tabular-nums">{{ c.hosts }}</TableCell>
            <TableCell class="text-right tabular-nums" :class="{ 'font-semibold text-sev-critical': c.openCritical > 0 }">{{ c.openCritical }}</TableCell>
            <TableCell class="text-right tabular-nums" :class="{ 'text-sev-high': c.openHigh > 0 }">{{ c.openHigh }}</TableCell>
            <TableCell class="max-w-72">
              <code v-if="c.scanConfig" class="block truncate text-xs" :title="JSON.stringify(c.scanConfig)">{{ JSON.stringify(c.scanConfig) }}</code>
              <span v-else class="text-sm text-muted-foreground">agent defaults</span>
            </TableCell>
            <TableCell class="text-sm text-muted-foreground">{{ formatDate(c.createdAt) }}</TableCell>
            <TableCell><Button size="sm" variant="outline" @click="editing = c">Scan config</Button></TableCell>
          </TableRow>
          <TableEmpty v-if="clients.isSuccess.value && !clients.data.value?.length" :colspan="7">
            No clients yet. Create one to get an enroll token.
          </TableEmpty>
        </TableBody>
      </Table>
    </Card>

    <CreateClientDialog v-model:open="creating" />
    <ScanConfigDialog :client="editing" @close="editing = null" />
  </div>
</template>
