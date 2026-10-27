<script setup lang="ts">
import { computed, ref } from 'vue'
import { toast } from 'vue-sonner'
import type { Host } from '@/domain/models'
import { type HostHealth, hostHealth, hostIssues } from '@/domain/rules'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/presentation/components/ui/alert-dialog'
import { Badge } from '@/presentation/components/ui/badge'
import { Button } from '@/presentation/components/ui/button'
import { Card } from '@/presentation/components/ui/card'
import { Table, TableBody, TableCell, TableEmpty, TableHead, TableHeader, TableRow } from '@/presentation/components/ui/table'
import { useHosts, useRevokeHost } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { errorMessage, formatDateTime, plural, relative } from '@/presentation/lib/format'

const { client } = useClientFilter()
const hosts = useHosts(client)
const revoke = useRevokeHost()
const showRevoked = ref(false)
const revoking = ref<Host | null>(null)

const rows = computed(() => (hosts.data.value ?? []).filter((h) => showRevoked.value || !h.revokedAt))
const dot: Record<HostHealth, string> = { healthy: 'bg-ok', attention: 'bg-sev-medium', stale: 'bg-sev-critical', revoked: 'bg-muted-foreground/40' }

async function confirmRevoke() {
  const h = revoking.value
  if (!h) return
  try {
    await revoke.mutateAsync(h.id)
    toast.success(`${h.client}/${h.hostname} revoked. Its agent must re-enroll to report again.`)
  } catch (e) {
    toast.error(errorMessage(e))
  } finally {
    revoking.value = null
  }
}
</script>

<template>
  <div class="grid gap-4">
    <div class="flex items-center justify-between">
      <p class="text-sm text-muted-foreground">{{ plural(rows.length, 'host') }}</p>
      <label class="flex items-center gap-2 text-sm text-muted-foreground">
        <input v-model="showRevoked" type="checkbox" class="accent-primary"> Show revoked
      </label>
    </div>
    <Card class="py-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Host</TableHead>
            <TableHead>System</TableHead>
            <TableHead>Last heartbeat</TableHead>
            <TableHead>Last scan</TableHead>
            <TableHead class="text-right">Critical</TableHead>
            <TableHead class="text-right">High</TableHead>
            <TableHead>Issues</TableHead>
            <TableHead class="w-24" />
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="h in rows" :key="h.id" :class="h.revokedAt && 'opacity-60'">
            <TableCell>
              <div class="flex items-center gap-2">
                <span :class="['size-2 shrink-0 rounded-full', dot[hostHealth(h)]]" :title="hostHealth(h)" />
                <div>
                  <div class="font-medium">{{ h.hostname }}</div>
                  <div class="text-xs text-muted-foreground">{{ h.client }}</div>
                </div>
              </div>
            </TableCell>
            <TableCell class="text-sm">
              <div>{{ h.osName }} {{ h.osVersion }} <span class="text-muted-foreground">{{ h.arch }}</span></div>
              <div class="text-xs text-muted-foreground">agent {{ h.agentVersion || '?' }} · trivy {{ h.trivyVersion || '?' }}</div>
            </TableCell>
            <TableCell class="text-sm" :class="h.staleHeartbeat && !h.revokedAt && 'text-sev-critical'" :title="formatDateTime(h.lastHeartbeatAt)">
              {{ relative(h.lastHeartbeatAt) }}
            </TableCell>
            <TableCell class="text-sm" :title="formatDateTime(h.lastScanAt)">
              <span :class="h.lastScanStatus === 'error' && 'text-sev-critical'">{{ relative(h.lastScanAt) }}</span>
              <span v-if="h.lastScanStatus === 'error'" class="block text-xs text-sev-critical">failed</span>
            </TableCell>
            <TableCell class="text-right tabular-nums">
              <RouterLink :to="{ name: 'findings', query: { client: h.client, host_id: h.id, severity: 'CRITICAL' } }" :class="{ 'font-semibold text-sev-critical hover:underline': h.openCritical > 0 }">
                {{ h.openCritical }}
              </RouterLink>
            </TableCell>
            <TableCell class="text-right tabular-nums">
              <RouterLink :to="{ name: 'findings', query: { client: h.client, host_id: h.id, severity: 'HIGH' } }" :class="{ 'text-sev-high hover:underline': h.openHigh > 0 }">
                {{ h.openHigh }}
              </RouterLink>
            </TableCell>
            <TableCell class="max-w-56">
              <div class="flex flex-wrap gap-1">
                <Badge v-for="i in hostIssues(h)" :key="i" variant="outline" class="text-[11px]">{{ i }}</Badge>
              </div>
            </TableCell>
            <TableCell>
              <Button v-if="!h.revokedAt" size="sm" variant="destructive" @click="revoking = h">Revoke</Button>
            </TableCell>
          </TableRow>
          <TableEmpty v-if="hosts.isSuccess.value && !rows.length" :colspan="8">No hosts enrolled yet.</TableEmpty>
        </TableBody>
      </Table>
    </Card>

    <AlertDialog :open="!!revoking" @update:open="(o) => !o && (revoking = null)">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke {{ revoking?.client }}/{{ revoking?.hostname }}?</AlertDialogTitle>
          <AlertDialogDescription>
            The host token stops working immediately, so the agent can no longer send reports or heartbeats.
            Finding history is kept. To bring the host back, re-enroll it with the client's enroll token.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction :disabled="revoke.isPending.value" @click="confirmRevoke">Revoke host</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </div>
</template>
