<script setup lang="ts">
import { Search } from '@lucide/vue'
import { computed, ref } from 'vue'
import type { Host } from '@/domain/models'
import { hostHealth, hostIssues } from '@/domain/rules'
import HostCard from '@/presentation/components/HostCard.vue'
import { Input } from '@/presentation/components/ui/input'
import { useHosts } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { plural } from '@/presentation/lib/format'

const { client } = useClientFilter()
const hosts = useHosts(client)
const search = ref('')
const showRevoked = ref(false)

const worstFirst = (a: Host, b: Host) =>
  Number(hostHealth(b) === 'stale') - Number(hostHealth(a) === 'stale')
  || b.openCritical - a.openCritical || b.openHigh - a.openHigh || a.hostname.localeCompare(b.hostname)

const visible = computed(() => {
  const q = search.value.trim().toLowerCase()
  return (hosts.data.value ?? [])
    .filter((h) => showRevoked.value || !h.revokedAt)
    .filter((h) => !q || h.hostname.toLowerCase().includes(q) || h.client.toLowerCase().includes(q))
})

const groups = computed(() => {
  const by = new Map<string, Host[]>()
  for (const h of visible.value) by.set(h.client, [...(by.get(h.client) ?? []), h])
  return [...by].map(([name, list]) => ({ name, hosts: list.sort(worstFirst) }))
})

const summary = computed(() => {
  const active = visible.value.filter((h) => !h.revokedAt)
  const count = (pred: (h: Host) => boolean) => active.filter(pred).length
  return [
    plural(active.length, 'host'),
    `${count((h) => h.openCritical > 0)} with critical findings`,
    `${count((h) => hostHealth(h) === 'stale')} not reporting`,
    `${count((h) => h.rebootRequired)} waiting for a reboot`,
  ]
})
</script>

<template>
  <div class="grid gap-6">
    <div class="flex flex-wrap items-center gap-3">
      <p class="text-sm text-muted-foreground">{{ summary.join(' · ') }}</p>
      <div class="relative ml-auto w-full sm:w-64">
        <Search class="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="search" class="pl-8" placeholder="Find a host" aria-label="Find a host" />
      </div>
      <label class="flex items-center gap-2 text-sm text-muted-foreground">
        <input v-model="showRevoked" type="checkbox" class="accent-primary"> Show revoked
      </label>
    </div>

    <p v-if="hosts.isSuccess.value && !groups.length" class="text-sm text-muted-foreground">
      No hosts yet. Create a client, then enroll its VMs with the Ansible role.
    </p>

    <section v-for="g in groups" :key="g.name" class="grid gap-3">
      <h2 class="text-sm font-medium">
        {{ g.name }} <span class="font-normal text-muted-foreground">· {{ plural(g.hosts.length, 'host') }}</span>
      </h2>
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <HostCard v-for="h in g.hosts" :key="h.id" :host="h" :issues="hostIssues(h)" />
      </div>
    </section>
  </div>
</template>
