<script setup lang="ts">
import { Ban, ChevronLeft, ChevronRight } from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { toast } from 'vue-sonner'
import type { Component, ComponentFilter, Finding, FindingFilter, TriageStatus } from '@/domain/models'
import { hostIssues, pageCount } from '@/domain/rules'
import ClientChip from '@/presentation/components/ClientChip.vue'
import ComponentItem from '@/presentation/components/ComponentItem.vue'
import ComponentTriageDialog from '@/presentation/components/ComponentTriageDialog.vue'
import CopyCommand from '@/presentation/components/CopyCommand.vue'
import FindingRow from '@/presentation/components/FindingRow.vue'
import TriageDialog from '@/presentation/components/TriageDialog.vue'
import UnderlineTabs from '@/presentation/components/UnderlineTabs.vue'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/presentation/components/ui/alert-dialog'
import { Button } from '@/presentation/components/ui/button'
import { useBreadcrumbs } from '@/presentation/composables/breadcrumbs'
import { useComponents, useFindings, useHosts, useRevokeHost } from '@/presentation/composables/queries'
import { errorMessage, formatDateTime, formatNumber, plural, relative } from '@/presentation/lib/format'

const route = useRoute()
const router = useRouter()
const id = computed(() => Number(route.params.id))
const hosts = useHosts(ref(undefined))
const host = computed(() => hosts.data.value?.find((h) => h.id === id.value))

useBreadcrumbs(() => [
  { label: 'Hosts', to: { name: 'hosts' } },
  ...(host.value ? [{ label: host.value.client, to: { name: 'hosts', query: { client: host.value.client } } }] : []),
  { label: host.value?.hostname ?? 'Host' },
])

type Tab = 'fix' | 'findings'
const tab = ref<Tab>('fix')

const status = ref<TriageStatus>('open')
const componentFilter = computed<ComponentFilter>(() => ({ hostId: id.value, status: status.value }))
const components = useComponents(componentFilter)

const findingsPage = ref(1)
const findingsFilter = computed<FindingFilter>(() => ({ hostId: id.value, status: 'open', sort: 'severity', page: findingsPage.value, pageSize: 50 }))
const findings = useFindings(findingsFilter)
watch(id, () => (findingsPage.value = 1))

const tabs = computed(() => [
  { value: 'fix' as const, label: 'What to fix' },
  { value: 'findings' as const, label: 'Findings', count: host.value ? host.value.openCritical + host.value.openHigh : undefined },
])

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

const statuses: { value: TriageStatus, label: string }[] = [
  { value: 'open', label: 'Open' }, { value: 'accepted', label: 'Accepted' }, { value: 'false_positive', label: 'False positive' },
]
const compGrid = 'grid grid-cols-[minmax(0,1fr)_3.5rem_3.5rem] items-center gap-x-4'
const findingGrid = 'grid grid-cols-[minmax(0,1fr)_4.5rem] items-center gap-x-4 md:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,1fr)_4.5rem]'
</script>

<template>
  <p v-if="hosts.isSuccess.value && !host" class="text-muted-foreground">Host not found.</p>

  <template v-if="host">
    <div class="flex flex-wrap items-start justify-between gap-6">
      <div class="min-w-0 space-y-1">
        <h1 class="text-[22px] font-semibold">{{ host.hostname }}</h1>
        <p class="flex flex-wrap items-center gap-x-2 gap-y-1 text-muted-foreground">
          <ClientChip :name="host.client" />
          <span>{{ host.osName }} {{ host.osVersion }} · {{ host.arch }} · kernel {{ host.kernelRunning || '?' }}</span>
        </p>
        <p v-for="issue in hostIssues(host)" :key="issue" class="inline-flex items-center gap-1.5 pr-3 text-[13px]">
          <span class="size-1.5 rounded-full bg-info" />{{ issue }}
        </p>
      </div>
      <div class="flex gap-6">
        <div>
          <p class="micro-cap text-muted-foreground">Open critical</p>
          <p class="mt-0.5 inline-flex items-center gap-1.5 text-[22px] font-semibold tabular-nums"><span class="size-2 rounded-[2px] bg-sev-critical" />{{ formatNumber(host.openCritical) }}</p>
        </div>
        <div>
          <p class="micro-cap text-muted-foreground">Open high</p>
          <p class="mt-0.5 inline-flex items-center gap-1.5 text-[22px] font-semibold tabular-nums"><span class="size-2 rounded-[2px] bg-sev-high" />{{ formatNumber(host.openHigh) }}</p>
        </div>
        <div>
          <p class="micro-cap text-muted-foreground">Last scan</p>
          <p class="mt-0.5 text-[22px] font-semibold" :title="formatDateTime(host.lastScanAt)">{{ relative(host.lastScanAt) }}</p>
        </div>
      </div>
    </div>

    <div class="flex flex-wrap items-center gap-3">
      <div class="min-w-0 flex-1 sm:max-w-md"><CopyCommand command="sudo vuln-agent scan" /></div>
      <span class="hidden text-[13px] text-muted-foreground lg:inline">Re-scan on the host after a fix.</span>
      <Button v-if="!host.revokedAt" variant="outline" class="ml-auto" @click="confirmingRevoke = true"><Ban /> Revoke</Button>
    </div>

    <UnderlineTabs v-model="tab" :tabs="tabs" />

    <div class="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
      <div v-if="tab === 'fix'" class="overflow-hidden rounded-md border bg-card self-start">
        <div :class="[compGrid, 'border-b bg-muted px-4 py-2.5 text-muted-foreground']">
          <div class="flex flex-wrap items-center gap-3">
            <span class="micro-cap">Component</span>
            <div class="ml-auto inline-flex divide-x divide-input rounded-sm border border-input text-[13px]" role="tablist">
              <button
                v-for="s in statuses" :key="s.value" type="button" role="tab" :aria-selected="status === s.value"
                class="px-2 py-1 font-medium aria-selected:bg-background aria-selected:text-foreground"
                @click="status = s.value"
              >{{ s.label }}</button>
            </div>
          </div>
          <span class="micro-cap text-right">Critical</span>
          <span class="micro-cap text-right">High</span>
        </div>
        <p v-if="components.isPending.value" class="px-4 py-6 text-muted-foreground">Loading…</p>
        <p v-else-if="components.isError.value" class="px-4 py-6 text-destructive">{{ components.error.value?.message }}</p>
        <p v-else-if="!components.data.value?.length" class="px-4 py-6 text-center text-muted-foreground">
          {{ status === 'open' ? 'Nothing open. This host is clean for critical and high findings.' : 'Nothing here.' }}
        </p>
        <ComponentItem
          v-for="c in components.data.value ?? []" :key="`${c.kind}|${c.key}`"
          :component="c" :host="host" :status="status" :grid="compGrid"
          @triage="(comp, title) => (triaging = { component: comp, title })"
          @triage-finding="(f) => (triagingFinding = f)"
        />
      </div>

      <div v-else class="self-start">
        <div class="overflow-hidden rounded-md border bg-card">
          <div :class="[findingGrid, 'border-b bg-muted px-4 py-2.5 text-muted-foreground']">
            <span class="micro-cap">CVE</span><span class="micro-cap hidden md:block">Package</span>
            <span class="micro-cap hidden md:block">Installed → fixed</span><span class="micro-cap text-right">Age</span>
          </div>
          <p v-if="findings.isSuccess.value && !findings.data.value?.items.length" class="px-4 py-6 text-center text-muted-foreground">No open findings.</p>
          <FindingRow v-for="f in findings.data.value?.items ?? []" :key="f.id" :finding="f" :grid="findingGrid" @triage="triagingFinding = f" />
        </div>
        <div v-if="findings.data.value && pageCount(findings.data.value) > 1" class="mt-3 flex items-center justify-end gap-2 text-[13px] text-muted-foreground">
          Page {{ findingsPage }} of {{ pageCount(findings.data.value) }}
          <Button size="icon-sm" variant="outline" aria-label="Previous page" :disabled="findingsPage <= 1" @click="findingsPage--"><ChevronLeft /></Button>
          <Button size="icon-sm" variant="outline" aria-label="Next page" :disabled="findingsPage >= pageCount(findings.data.value)" @click="findingsPage++"><ChevronRight /></Button>
        </div>
      </div>

      <aside class="space-y-4">
        <section class="space-y-2 border-b pb-4">
          <h3 class="micro-cap text-muted-foreground">Last scan</h3>
          <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5">
            <dt class="text-muted-foreground">Status</dt>
            <dd class="text-right">
              <span class="inline-flex items-center gap-1.5">
                <span class="size-1.5 rounded-full" :class="host.lastScanStatus === 'error' ? 'bg-sev-critical' : host.lastScanStatus === 'ok' ? 'bg-ok' : 'bg-muted-foreground'" />
                {{ host.lastScanStatus === 'error' ? 'failed' : host.lastScanStatus || 'none yet' }}
              </span>
            </dd>
            <template v-if="host.lastScanStatus === 'ok' && !host.firstScan">
              <dt class="text-muted-foreground">Resolved</dt><dd class="text-right">{{ formatNumber(host.resolvedInLastScan) }}</dd>
              <dt class="text-muted-foreground">New</dt><dd class="text-right">{{ formatNumber(host.newInLastScan) }}</dd>
            </template>
            <dt class="text-muted-foreground">Scanned</dt><dd class="truncate text-right" :title="formatDateTime(host.lastScanAt)">{{ relative(host.lastScanAt) }}</dd>
          </dl>
        </section>
        <section class="space-y-2 border-b pb-4">
          <h3 class="micro-cap text-muted-foreground">Host details</h3>
          <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5">
            <dt class="text-muted-foreground">Client</dt><dd class="truncate text-right">{{ host.client }}</dd>
            <dt class="text-muted-foreground">Heartbeat</dt><dd class="truncate text-right" :title="formatDateTime(host.lastHeartbeatAt)">{{ relative(host.lastHeartbeatAt) }}</dd>
            <dt class="text-muted-foreground">Agent</dt><dd class="truncate text-right">{{ host.agentVersion || '?' }}</dd>
            <dt class="text-muted-foreground">Trivy</dt><dd class="truncate text-right">{{ host.trivyVersion || '?' }}</dd>
            <dt class="text-muted-foreground">Accepted</dt><dd class="text-right">{{ plural(host.accepted, 'finding') }}</dd>
            <dt class="text-muted-foreground">False positive</dt><dd class="text-right">{{ plural(host.falsePositive, 'finding') }}</dd>
            <dt class="text-muted-foreground">Enrolled</dt><dd class="truncate text-right">{{ formatDateTime(host.createdAt) }}</dd>
          </dl>
        </section>
        <section class="space-y-2">
          <h3 class="micro-cap text-muted-foreground">Tags</h3>
          <div class="flex flex-wrap gap-1.5">
            <span
              v-for="[k, v] in [['os', `${host.osName} ${host.osVersion}`.trim()], ['arch', host.arch], ['kernel', host.kernelRunning], ['reboot', host.rebootRequired ? 'required' : 'no'], ['auto-update', host.autoUpdateEnabled ? 'on' : 'off']].filter(([, v]) => v)"
              :key="k"
              class="rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[13px]"
            ><span class="text-muted-foreground">{{ k }}:</span>{{ v }}</span>
          </div>
        </section>
      </aside>
    </div>
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
          Finding history is kept. To bring the host back, enroll it again.
        </AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <AlertDialogAction :disabled="revoke.isPending.value" @click="confirmRevoke">Revoke host</AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
