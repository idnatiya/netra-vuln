<script setup lang="ts">
import { ChevronRight, ChevronsUpDown, LogOut, Search, Server, ShieldCheck, Users } from '@lucide/vue'
import { useQueryClient } from '@tanstack/vue-query'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { crumbs } from '@/presentation/composables/breadcrumbs'
import { session } from '@/presentation/composables/session'
import { useUseCases } from '@/presentation/composables/useUseCases'
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupLabel, SidebarHeader, SidebarInset,
  SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarTrigger,
} from '@/presentation/components/ui/sidebar'

const route = useRoute()
const router = useRouter()
const uc = useUseCases()
const qc = useQueryClient()

const groups = [
  { label: 'Monitor', items: [
    { name: 'hosts', label: 'Hosts', icon: Server, match: ['hosts', 'host'] },
    { name: 'findings', label: 'Search CVEs', icon: Search, match: ['findings'] },
  ] },
  { label: 'Manage', items: [
    { name: 'clients', label: 'Clients', icon: Users, match: ['clients'] },
  ] },
]

const header = computed(() => crumbs.value ?? [{ label: String(route.meta.title ?? '') }])

const expiresIn = computed(() => {
  if (!session.value) return ''
  const h = Math.round((session.value.expiresAt.getTime() - Date.now()) / 3_600_000)
  return h >= 1 ? `Expires in ${h}h` : 'Expires soon'
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
  <SidebarProvider>
    <Sidebar variant="inset">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" as-child>
              <RouterLink :to="{ name: 'hosts' }">
                <span class="flex size-8 items-center justify-center rounded-lg bg-gold text-ink"><ShieldCheck class="size-4" /></span>
                <span class="grid flex-1 leading-tight">
                  <span class="truncate font-semibold">netra-vuln</span>
                  <span class="truncate text-[13px] text-muted-foreground">Vulnerability central</span>
                </span>
              </RouterLink>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup v-for="g in groups" :key="g.label">
          <SidebarGroupLabel>{{ g.label }}</SidebarGroupLabel>
          <SidebarMenu>
            <SidebarMenuItem v-for="item in g.items" :key="item.name">
              <SidebarMenuButton as-child :is-active="item.match.includes(String(route.name))" class="h-9 text-[15px]">
                <RouterLink :to="{ name: item.name }"><component :is="item.icon" />{{ item.label }}</RouterLink>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem class="flex items-center gap-1">
            <SidebarMenuButton size="lg" class="flex-1" as-child :is-active="route.name === 'account'">
              <RouterLink :to="{ name: 'account' }">
              <span class="flex size-8 shrink-0 items-center justify-center rounded-lg bg-brand font-semibold">
                {{ session?.username.charAt(0).toUpperCase() }}
              </span>
              <span class="grid min-w-0 flex-1 leading-tight">
                <span class="truncate font-medium">{{ session?.username }}</span>
                <span class="truncate text-[13px] text-muted-foreground">{{ expiresIn }}</span>
              </span>
              <ChevronsUpDown class="ml-auto text-muted-foreground" />
              </RouterLink>
            </SidebarMenuButton>
            <button
              type="button"
              title="Sign out"
              aria-label="Sign out"
              class="inline-flex size-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
              @click="logout"
            >
              <LogOut class="size-4" />
            </button>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>

    <SidebarInset class="min-w-0 md:peer-data-[variant=inset]:border">
      <header class="flex h-14 shrink-0 items-center gap-2 px-4 sm:px-6 lg:px-8">
        <SidebarTrigger class="-ml-1.5 text-muted-foreground" />
        <span aria-hidden="true" class="mr-1 h-4 w-px bg-border" />
        <nav aria-label="Breadcrumb" class="flex min-w-0 items-center">
          <template v-for="(c, i) in header" :key="i">
            <ChevronRight v-if="i" class="mx-1.5 size-3.5 shrink-0 text-muted-foreground" />
            <RouterLink v-if="c.to && i < header.length - 1" :to="c.to" class="hidden text-muted-foreground hover:text-foreground sm:inline">{{ c.label }}</RouterLink>
            <span v-else :class="i < header.length - 1 ? 'text-muted-foreground' : 'truncate'">{{ c.label }}</span>
          </template>
        </nav>
      </header>
      <div class="grid w-full min-w-0 flex-1 grid-cols-1 content-start gap-5 p-4 pt-2 pb-12 sm:p-6 sm:pt-2 lg:px-8">
        <RouterView />
      </div>
    </SidebarInset>
  </SidebarProvider>
</template>
