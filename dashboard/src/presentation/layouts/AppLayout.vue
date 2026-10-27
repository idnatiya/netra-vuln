<script setup lang="ts">
import { Building2, LayoutDashboard, LogOut, Server, ShieldAlert, ShieldCheck } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { session } from '@/presentation/composables/session'
import { useClients } from '@/presentation/composables/queries'
import { useClientFilter } from '@/presentation/composables/useClientFilter'
import { useUseCases } from '@/presentation/composables/useUseCases'
import { Button } from '@/presentation/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/presentation/components/ui/select'

const ALL = '__all__' // reka Select cannot use '' as a value
const route = useRoute()
const router = useRouter()
const uc = useUseCases()
const qc = useQueryClient()
const { client } = useClientFilter()
const clients = useClients()

const nav = [
  { name: 'overview', label: 'Overview', icon: LayoutDashboard },
  { name: 'findings', label: 'Findings', icon: ShieldAlert },
  { name: 'hosts', label: 'Hosts', icon: Server },
  { name: 'clients', label: 'Clients', icon: Building2 },
] as const

const selected = computed({
  get: () => client.value ?? ALL,
  set: (v: string) => (client.value = v === ALL ? undefined : v),
})

async function logout() {
  try {
    await uc.logout()
  } finally {
    session.value = null
    qc.clear()
    router.push({ name: 'login' })
  }
}
</script>

<template>
  <div class="min-h-svh bg-muted/30 md:grid md:grid-cols-[13rem_1fr]">
    <aside class="hidden border-r bg-background md:flex md:flex-col">
      <div class="flex h-14 items-center gap-2 border-b px-4 font-semibold">
        <ShieldCheck class="size-5 text-primary" /> Vuln Central
      </div>
      <nav class="grid gap-1 p-2 text-sm">
        <RouterLink
          v-for="item in nav"
          :key="item.name"
          :to="{ name: item.name, query: client ? { client } : {} }"
          class="flex items-center gap-2 rounded-md px-3 py-2 text-muted-foreground hover:bg-muted hover:text-foreground"
          exact-active-class="bg-muted font-medium !text-foreground"
        >
          <component :is="item.icon" class="size-4" /> {{ item.label }}
        </RouterLink>
      </nav>
    </aside>

    <div class="flex min-w-0 flex-col">
      <header class="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background/95 px-4 backdrop-blur">
        <nav class="flex gap-1 text-sm md:hidden">
          <RouterLink
            v-for="item in nav"
            :key="item.name"
            :to="{ name: item.name, query: client ? { client } : {} }"
            :aria-label="item.label"
            class="rounded-md p-2 text-muted-foreground"
            exact-active-class="bg-muted !text-foreground"
          >
            <component :is="item.icon" class="size-4" />
          </RouterLink>
        </nav>
        <h1 class="hidden text-sm font-medium md:block">{{ nav.find((n) => n.name === route.name)?.label }}</h1>
        <div class="ml-auto flex items-center gap-2">
          <Select v-model="selected">
            <SelectTrigger class="w-44" aria-label="Client filter">
              <SelectValue placeholder="All clients" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem :value="ALL">All clients</SelectItem>
              <SelectItem v-for="c in clients.data.value ?? []" :key="c.name" :value="c.name">{{ c.name }}</SelectItem>
            </SelectContent>
          </Select>
          <span class="hidden text-sm text-muted-foreground sm:inline">{{ session?.username }}</span>
          <Button variant="ghost" size="icon" aria-label="Log out" @click="logout"><LogOut class="size-4" /></Button>
        </div>
      </header>
      <main class="mx-auto w-full max-w-7xl flex-1 p-4 md:p-6">
        <RouterView />
      </main>
    </div>
  </div>
</template>
