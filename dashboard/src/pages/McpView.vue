<script setup lang="ts">
import { computed, ref } from 'vue'
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { toast } from 'vue-sonner'
import { api } from '@/apis'
import { errorMessage, formatDateTime, relative } from '@/lib/format'
import { mcpClientConfigs } from '@/lib/rules'
import PageHeader from '@/components/PageHeader.vue'
import CopyCommand from '@/components/CopyCommand.vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

const qc = useQueryClient()
const url = `${window.location.origin}/mcp`
const name = ref('')
const canTriage = ref(false)
const token = ref('')
const tab = ref('claude-code')

const tokens = useQuery({ queryKey: ['mcp-tokens'], queryFn: api.listMcpTokens })
const create = useMutation({
  mutationFn: () => api.createMcpToken(name.value, canTriage.value),
  onSuccess: (t) => { token.value = t.token; name.value = ''; canTriage.value = false; qc.invalidateQueries({ queryKey: ['mcp-tokens'] }) },
  onError: (e) => toast.error(errorMessage(e)),
})
const revoke = useMutation({
  mutationFn: (id: number) => api.revokeMcpToken(id),
  onSuccess: () => { toast.success('Token revoked.'); qc.invalidateQueries({ queryKey: ['mcp-tokens'] }) },
  onError: (e) => toast.error(errorMessage(e)),
})

const configs = computed(() => mcpClientConfigs(url, token.value || '<your-token>'))
const current = computed(() => configs.value.find((c) => c.id === tab.value) ?? configs.value[0]!)
const examples = [
  'Which hosts have open critical vulnerabilities?',
  'Which hosts are affected by CVE-2024-6387?',
  'What should I fix first on <hostname>?',
  'Summarize open critical and high findings per client.',
  'Accept CVE-… on <hostname>: fix planned next maintenance window. (triage token)',
]
</script>

<template>
  <PageHeader title="MCP" description="Ask an AI assistant (Claude, Codex, OpenCode, Antigravity, Cursor, …) about your vulnerabilities. Read-only by default; triage only with tokens that allow it." />
  <div class="grid max-w-4xl gap-8">
    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">1</span>
      <div><h2 class="text-[17px] font-semibold">Create a token</h2><p class="text-muted-foreground">One token per device or tool, so you can revoke it alone.</p></div>
      <form class="col-start-2 flex flex-wrap items-center gap-3" @submit.prevent="create.mutate()">
        <Input v-model="name" aria-label="Token name" placeholder="e.g. laptop-claude-code" maxlength="64" class="w-64" />
        <Button type="submit" :disabled="create.isPending.value">Create token</Button>
        <label class="flex w-full items-start gap-2 text-muted-foreground">
          <input v-model="canTriage" type="checkbox" class="mt-1 accent-primary">
          <span>Allow triage: the AI may accept, mark false positive, or reopen findings (it asks you first; notes get “[via MCP: name]”). Leave off for read-only.</span>
        </label>
      </form>
      <p v-if="token" class="col-start-2 rounded-md border-l-4 border-gold bg-muted px-3 py-2">
        The token is in the setup below and is shown only once. It can read every client's findings: keep it private.
      </p>
    </section>

    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">2</span>
      <div><h2 class="text-[17px] font-semibold">Add it to your AI client</h2><p class="text-muted-foreground">Pick the client, copy, and restart it if needed.<template v-if="!token"> Create a token first to fill it in.</template></p></div>
      <div class="col-start-2 overflow-hidden rounded-md border">
        <div class="flex flex-wrap border-b bg-muted text-sm" role="tablist" aria-label="AI client">
          <button v-for="c in configs" :key="c.id" role="tab" :aria-selected="tab === c.id" class="border-b-2 border-transparent px-3 py-2 aria-selected:border-foreground" @click="tab = c.id">{{ c.label }}</button>
        </div>
        <p class="px-4 pt-3 text-muted-foreground">{{ current.where }}</p>
        <div class="p-3"><CopyCommand :command="current.snippet" /></div>
      </div>
    </section>

    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">3</span>
      <div><h2 class="text-[17px] font-semibold">Ask</h2><p class="text-muted-foreground">Tools: list_clients, list_hosts, search_findings, host_components; with triage also triage_finding, triage_component.</p></div>
      <ul class="col-start-2 grid gap-1.5">
        <li v-for="q in examples" :key="q" class="rounded-md bg-muted/40 px-3 py-2">“{{ q }}”</li>
      </ul>
    </section>

    <section class="grid gap-3">
      <h2 class="text-[17px] font-semibold">Your tokens</h2>
      <p v-if="tokens.isError.value" role="alert">Could not load tokens.</p>
      <p v-else-if="tokens.isSuccess.value && !tokens.data.value?.length" class="text-muted-foreground">No tokens yet.</p>
      <div v-else class="overflow-hidden rounded-md border bg-card">
        <div v-for="t in tokens.data.value" :key="t.id" class="flex flex-wrap items-center gap-x-6 gap-y-1 border-b px-4 py-3 last:border-b-0">
          <span class="min-w-40 flex-1 font-medium">{{ t.name }} <span v-if="t.canTriage" class="ml-1 rounded-sm border border-gold px-1.5 py-0.5 text-[12px] font-normal text-gold">Triage</span></span>
          <span class="text-muted-foreground" :title="formatDateTime(t.createdAt)">Created {{ relative(t.createdAt) }}</span>
          <span class="text-muted-foreground">{{ t.lastUsedAt ? `Used ${relative(t.lastUsedAt)}` : 'Never used' }}</span>
          <Button variant="outline" size="sm" :disabled="revoke.isPending.value" @click="revoke.mutate(t.id)">Revoke</Button>
        </div>
      </div>
    </section>
  </div>
</template>
