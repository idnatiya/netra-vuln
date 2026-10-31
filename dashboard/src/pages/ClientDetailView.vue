<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import PageHeader from '@/components/PageHeader.vue'
import ScanConfigDialog from '@/components/ScanConfigDialog.vue'
import TrendSparkline from '@/components/TrendSparkline.vue'
import { Button } from '@/components/ui/button'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { useBreadcrumbs } from '@/composables/breadcrumbs'
import { useClients, useDeleteClient, useHosts } from '@/composables/queries'
import { errorMessage, formatDate, formatNumber, plural } from '@/lib/format'

const route = useRoute()
const router = useRouter()
const name = computed(() => String(route.params.name))
const clients = useClients()
const hosts = useHosts(name)
const activeHosts = computed(() => (hosts.data.value ?? []).filter(h => !h.revokedAt).length)
const revokedHosts = computed(() => (hosts.data.value ?? []).filter(h => h.revokedAt).length)
const totalHosts = computed(() => (hosts.data.value ?? []).length)
const canDelete = computed(() => hosts.isSuccess.value && !hosts.isFetching.value && totalHosts.value === 0)
const client = computed(() => clients.data.value?.find(c => c.name === name.value))
const editing = ref(false)
const confirming = ref(false)
const deletion = useDeleteClient()
useBreadcrumbs(() => [{ label: 'Clients', to: { name: 'clients' } }, { label: name.value }])
async function remove() {
  if (!canDelete.value || deletion.isPending.value) return
  try {
    await deletion.mutateAsync(name.value)
    toast.success('Client deleted')
    await router.push({ name: 'clients' })
  } catch (e) { toast.error(errorMessage(e)) }
}
</script>

<template>
  <p v-if="clients.isPending.value">Loading client…</p>
  <p v-else-if="clients.isError.value" role="alert">Could not load client: {{ errorMessage(clients.error.value) }}</p>
  <div v-else-if="!client" class="space-y-3"><p>Client not found.</p><RouterLink class="underline" :to="{ name: 'clients' }">Back to clients</RouterLink></div>
  <template v-else>
    <PageHeader :title="client.name" :description="`Client since ${formatDate(client.createdAt)}`">
      <Button as-child><RouterLink :to="{ name: 'add-agent', query: { client: client.name } }">Add agent</RouterLink></Button>
    </PageHeader>
    <div class="grid gap-4 sm:grid-cols-3">
      <RouterLink :to="{ name: 'hosts', query: { client: client.name } }" class="rounded-md border bg-card p-4 hover:bg-muted">
        <p class="text-muted-foreground">Active hosts</p>
        <template v-if="hosts.isSuccess.value">
          <p class="text-xl font-semibold">{{ formatNumber(activeHosts) }}</p>
          <p class="text-sm text-muted-foreground">Revoked hosts: {{ formatNumber(revokedHosts) }}</p>
          <span class="text-sm underline">View {{ plural(totalHosts, 'host') }} total</span>
        </template>
        <p v-else class="text-sm text-muted-foreground">{{ hosts.isError.value ? 'Host counts unavailable' : 'Loading hosts…' }}</p>
      </RouterLink>
      <div class="rounded-md border bg-card p-4"><p class="text-muted-foreground">Open critical</p><p class="text-xl font-semibold">{{ formatNumber(client.openCritical) }}</p></div>
      <div class="rounded-md border bg-card p-4"><p class="text-muted-foreground">Open high</p><p class="text-xl font-semibold">{{ formatNumber(client.openHigh) }}</p></div>
    </div>
    <div class="rounded-md border bg-card p-4"><h2 class="font-semibold">Finding trend</h2><TrendSparkline :client="client.name" :level="client.openCritical ? 'critical' : client.openHigh ? 'high' : 'clean'" :width="600" class="mt-4 h-12 w-full" /></div>
    <div class="rounded-md border bg-card p-4"><h2 class="font-semibold">Scan configuration</h2><p class="my-2 text-muted-foreground">{{ client.scanConfig ? 'Custom scan configuration' : 'Agent defaults' }}</p><pre v-if="client.scanConfig" class="mb-3 overflow-auto text-sm">{{ JSON.stringify(client.scanConfig, null, 2) }}</pre><Button variant="outline" @click="editing = true">Scan config</Button></div>
    <div class="rounded-md border bg-card p-4">
      <h2 class="font-semibold">Delete client</h2>
      <p v-if="hosts.isError.value" role="alert" class="my-2 text-muted-foreground">Could not check hosts. Reload host data before deleting this client.</p>
      <p v-else-if="hosts.isPending.value" class="my-2 text-muted-foreground">Checking hosts before deletion…</p>
      <p v-else-if="totalHosts > 0" class="my-2 text-muted-foreground">Cannot delete this client: {{ plural(totalHosts, 'host') }} remain ({{ activeHosts }} active, {{ revokedHosts }} revoked). Revoked hosts retain their history and also prevent deletion.</p>
      <p v-else class="my-2 text-muted-foreground">This client has no hosts and can be permanently deleted.</p>
      <div class="flex flex-wrap items-center gap-3">
        <Button variant="destructive" :disabled="!canDelete || deletion.isPending.value" @click="confirming = true">Delete client</Button>
        <Button v-if="hosts.isError.value" variant="outline" :disabled="hosts.isFetching.value" @click="hosts.refetch()">Retry</Button>
        <RouterLink v-if="totalHosts > 0" class="underline" :to="{ name: 'hosts', query: { client: client.name } }">View client hosts</RouterLink>
      </div>
    </div>
    <ScanConfigDialog :client="editing ? client : null" @close="editing = false" />
    <AlertDialog :open="confirming" @update:open="confirming = $event"><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete {{ client.name }}?</AlertDialogTitle><AlertDialogDescription>This permanently deletes the client and its unused enrollment tokens. Clients with hosts cannot be deleted.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction :disabled="!canDelete || deletion.isPending.value" @click.prevent="remove">Delete client</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </template>
</template>
