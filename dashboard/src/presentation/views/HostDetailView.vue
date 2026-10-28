<script setup lang="ts">
import { ArrowLeft } from '@lucide/vue'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import type { Component, ComponentFilter, Finding, TriageStatus } from '@/domain/models'
import { hostIssues } from '@/domain/rules'
import ComponentItem from '@/presentation/components/ComponentItem.vue'
import ComponentTriageDialog from '@/presentation/components/ComponentTriageDialog.vue'
import CopyCommand from '@/presentation/components/CopyCommand.vue'
import TriageDialog from '@/presentation/components/TriageDialog.vue'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/presentation/components/ui/alert-dialog'
import { Button } from '@/presentation/components/ui/button'
import { useComponents, useHosts, useRevokeHost } from '@/presentation/composables/queries'
import { errorMessage, formatDateTime, formatNumber, plural, relative } from '@/presentation/lib/format'

const route = useRoute()
const router = useRouter()
const id = computed(() => Number(route.params.id))
const hosts = useHosts(ref(undefined))
const host = computed(() => hosts.data.value?.find((h) => h.id === id.value))

const status = ref<TriageStatus>('open')
const filter = computed<ComponentFilter>(() => ({ hostId: id.value, status: status.value }))
const components = useComponents(filter)

const triaging = ref<{ component: Component, title: string } | null>(null)
const triagingFinding = ref<Finding | null>(null)

const revoke = useRevokeHost()
const confirmingRevoke = ref(false)
async function confirmRevoke() {
  if (!host.value) return
  try {
    await revoke.mutateAsync(host.value.id)
    toast.success(`${host.value.hostname} revoked. Its agent must re-enroll to report again.`)
    router.push({ name: 'hosts' })
  } catch (e) {
    toast.error(errorMessage(e))
  } finally {
    confirmingRevoke.value = false
  }
}

const tabs: { value: TriageStatus, label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'accepted', label: 'Accepted' },
  { value: 'false_positive', label: 'False positive' },
]
</script>

<template>
  <div class="grid gap-6">
    <RouterLink :to="{ name: 'hosts' }" class="inline-flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ArrowLeft class="size-4" /> Hosts
    </RouterLink>

    <p v-if="hosts.isSuccess.value && !host" class="text-sm text-muted-foreground">Host not found.</p>

    <template v-if="host">
      <header class="flex flex-wrap items-start gap-4">
        <div class="min-w-0 flex-1">
          <h2 class="text-xl font-semibold">{{ host.hostname }}</h2>
          <p class="mt-1 text-sm text-muted-foreground">
            {{ host.client }} · {{ host.osName }} {{ host.osVersion }} · {{ host.arch }} · kernel {{ host.kernelRunning || '?' }}
          </p>
          <p class="mt-1 text-xs text-muted-foreground">
            Scanned <span :title="formatDateTime(host.lastScanAt)">{{ relative(host.lastScanAt) }}</span><template v-if="host.lastScanStatus === 'error'"> <span class="text-sev-critical">(failed)</span></template>
            · heartbeat <span :title="formatDateTime(host.lastHeartbeatAt)">{{ relative(host.lastHeartbeatAt) }}</span>
            · agent {{ host.agentVersion || '?' }} · trivy {{ host.trivyVersion || '?' }}
          </p>
          <p v-if="hostIssues(host).length" class="mt-1 text-xs text-sev-high">{{ hostIssues(host).join(' · ') }}</p>
        </div>
        <Button v-if="!host.revokedAt" variant="outline" size="sm" class="text-destructive" @click="confirmingRevoke = true">Revoke</Button>
      </header>

      <div class="grid gap-4 rounded-lg border bg-background p-4 sm:grid-cols-[auto_auto_1fr] sm:items-center sm:gap-8">
        <p class="tabular-nums">
          <span class="text-3xl font-semibold" :class="host.openCritical ? 'text-sev-critical' : 'text-muted-foreground'">{{ formatNumber(host.openCritical) }}</span>
          <span class="ml-1 text-sm text-muted-foreground">open critical</span>
        </p>
        <p class="tabular-nums">
          <span class="text-3xl font-semibold" :class="!host.openHigh && 'text-muted-foreground'">{{ formatNumber(host.openHigh) }}</span>
          <span class="ml-1 text-sm text-muted-foreground">open high</span>
        </p>
        <div class="grid gap-2 text-sm">
          <p v-if="host.lastScanStatus !== 'ok'" class="text-muted-foreground">No successful scan to compare yet.</p>
          <p v-else-if="host.firstScan" class="text-muted-foreground">First scan; changes show up from the next one.</p>
          <p v-else>
            Last scan: <span class="font-medium text-ok">{{ plural(host.resolvedInLastScan, 'finding') }} resolved</span>,
            <span :class="{ 'font-medium text-sev-high': host.newInLastScan > 0 }">{{ formatNumber(host.newInLastScan) }} new</span>.
          </p>
          <p class="text-xs text-muted-foreground">After fixing something, re-scan on the host:</p>
          <CopyCommand command="sudo vuln-agent scan" />
        </div>
      </div>

      <section class="grid gap-3">
        <div class="flex flex-wrap items-center gap-3">
          <h3 class="text-sm font-medium">What to fix</h3>
          <div class="ml-auto flex rounded-md border p-0.5 text-sm" role="tablist">
            <button
              v-for="t in tabs" :key="t.value" type="button" role="tab" :aria-selected="status === t.value"
              class="rounded px-3 py-1 text-muted-foreground aria-selected:bg-muted aria-selected:text-foreground"
              @click="status = t.value"
            >{{ t.label }}</button>
          </div>
        </div>
        <p v-if="components.isPending.value" class="text-sm text-muted-foreground">Loading…</p>
        <p v-else-if="components.isError.value" class="text-sm text-destructive">{{ components.error.value?.message }}</p>
        <p v-else-if="!components.data.value?.length" class="text-sm text-muted-foreground">
          {{ status === 'open' ? 'Nothing open. This host is clean for critical and high findings.' : 'Nothing here.' }}
        </p>
        <ComponentItem
          v-for="c in components.data.value ?? []" :key="`${c.kind}|${c.key}`"
          :component="c" :host="host" :status="status"
          @triage="(comp, title) => (triaging = { component: comp, title })"
          @triage-finding="(f) => (triagingFinding = f)"
        />
      </section>
    </template>

    <ComponentTriageDialog
      :component="triaging?.component ?? null" :title="triaging?.title ?? ''" :current="status"
      @close="triaging = null"
    />
    <TriageDialog :finding="triagingFinding" @close="triagingFinding = null" />

    <AlertDialog :open="confirmingRevoke" @update:open="(o) => !o && (confirmingRevoke = false)">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Revoke {{ host?.client }}/{{ host?.hostname }}?</AlertDialogTitle>
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
