<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useMutation, useQuery } from '@tanstack/vue-query'
import { api } from '@/apis'
import { useClients } from '@/composables/queries'
import PageHeader from '@/components/PageHeader.vue'
import CopyCommand from '@/components/CopyCommand.vue'
import { Button } from '@/components/ui/button'

const route = useRoute()
const client = ref(typeof route.query.client === 'string' ? route.query.client : '')
const token = ref('')
const tab = ref<'one' | 'manual'>('one')
const baseline = ref(new Map<number, boolean>())
const clients = useClients()
const info = useQuery({ queryKey: ['install-info'], queryFn: api.installInfo })
const hosts = useQuery({ queryKey: computed(() => ['install-hosts', client.value]), queryFn: () => api.listHosts(client.value), enabled: computed(() => !!token.value && !!client.value), refetchInterval: 5000 })
const added = computed(() => (hosts.data.value ?? []).filter(h => !h.revokedAt && (!baseline.value.has(h.id) || baseline.value.get(h.id))))
const rotate = useMutation({ mutationFn: async () => {
  const current = await api.listHosts(client.value)
  baseline.value = new Map(current.map(h => [h.id, !!h.revokedAt]))
  return api.issueEnrollToken(client.value)
}, onSuccess: value => { token.value = value } })

watch(client, () => { token.value = ''; baseline.value.clear() })
const command = computed(() => `export VULN_AGENT_ENROLL_TOKEN='${token.value}'\ncurl -fsSL '${info.data.value?.publicUrl}/install.sh' | sudo --preserve-env=VULN_AGENT_ENROLL_TOKEN sh -s -- '${client.value}'`)
const manual = computed(() => `a=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
u=https://github.com/idnatiya/netra-vuln-agent/releases/download/${info.data.value?.agentVersion}
curl -fsSLO "$u/vuln-agent-linux-$a" -fsSLO "$u/SHA256SUMS"
grep " vuln-agent-linux-$a\$" SHA256SUMS | sha256sum -c -
chmod +x "vuln-agent-linux-$a"
sudo "./vuln-agent-linux-$a" install -central-url '${info.data.value?.publicUrl}' -client-id '${client.value}'
sudo vuln-agent enroll`)
</script>

<template>
  <PageHeader title="Add agent" description="Run one command on a VM. The agent installs itself, enrolls, and sends its first scan here." />
  <div class="grid max-w-4xl gap-8">
    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">1</span>
      <div><h2 class="text-[17px] font-semibold">Choose the client</h2><p class="text-muted-foreground">The VM's findings belong to this client.</p></div>
      <div class="col-start-2 flex flex-wrap items-center gap-3">
        <select v-model="client" aria-label="Client" class="h-9 rounded border bg-muted/40 px-3">
          <option value="">Select a client</option><option v-for="c in clients.data.value" :key="c.name" :value="c.name">{{ c.name }}</option>
        </select>
        <RouterLink :to="{ name: 'clients' }" class="text-muted-foreground underline">Create a client</RouterLink>
      </div>
      <p v-if="clients.isError.value" class="col-start-2" role="alert">Could not load clients.</p>
    </section>
    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">2</span>
      <div><h2 class="text-[17px] font-semibold">Install</h2><p class="text-muted-foreground">Run as root or with sudo on the VM. Safe to run again to update.</p></div>
      <div class="col-start-2 grid gap-3">
        <p v-if="info.isError.value" role="alert">Could not load installer settings.</p>
        <p v-else-if="info.data.value && !info.data.value.enabled" role="alert">Installer is disabled. Configure CENTRAL_PUBLIC_URL and CENTRAL_AGENT_VERSION on central.</p>
        <Button class="w-fit" :disabled="!client || !info.data.value?.enabled || rotate.isPending.value" @click="rotate.mutate()">{{ token ? 'Generate another token' : 'Generate enroll token' }}</Button>
        <p v-if="rotate.isError.value" role="alert">Could not generate token: {{ rotate.error.value?.message }}</p>
        <template v-if="token">
          <div class="overflow-hidden rounded-md border">
            <div class="flex border-b bg-muted text-sm" role="tablist" aria-label="Install method">
              <button v-for="item in [{ id: 'one', label: 'One line' }, { id: 'manual', label: 'Manual' }]" :key="item.id" role="tab" :aria-selected="tab === item.id" class="border-b-2 px-3 py-2 aria-selected:border-foreground" @click="tab = item.id as 'one' | 'manual'">{{ item.label }}</button>
            </div>
            <CopyCommand :command="tab === 'one' ? command : manual" />
          </div>
          <p v-if="tab === 'manual'" class="text-muted-foreground">Enter the enrollment token when prompted. Start the first scan with <code>sudo systemctl start vuln-agent-scan.service</code>.</p>
          <p class="rounded-md border-l-4 border-gold bg-muted px-3 py-2">This token can enroll one agent for {{ client }}. Share it only with people who manage this VM.</p>
        </template>
        <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5"><dt class="text-muted-foreground">Supported</dt><dd>Ubuntu, Debian, AlmaLinux, Rocky, CentOS · amd64, arm64</dd><dt class="text-muted-foreground">Network</dt><dd>Outbound access to central and github.com</dd><dt class="text-muted-foreground">Runs</dt><dd>Daily scan, heartbeat every 15 minutes</dd></dl>
      </div>
    </section>
    <section class="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-4 gap-y-3">
      <span class="flex size-7 items-center justify-center rounded-full border font-semibold">3</span>
      <div><h2 class="text-[17px] font-semibold">Verify</h2><p class="text-muted-foreground">Optional: check the config, Trivy, and the connection to central.</p></div>
      <div class="col-start-2"><CopyCommand command="sudo vuln-agent check" /></div>
    </section>
  </div>
  <div v-if="token" class="sticky bottom-0 mt-8 flex flex-wrap items-center gap-3 border-t bg-sidebar/95 px-4 py-3">
    <span v-if="!added.length" class="text-muted-foreground">Waiting for agents from {{ client }}…</span>
    <span v-else>{{ added.length }} agent{{ added.length > 1 ? 's' : '' }} connected to {{ client }}</span>
    <span v-if="hosts.isError.value" role="alert">Could not load hosts.</span>
    <RouterLink v-for="host in added" :key="host.id" class="ml-auto rounded bg-primary px-3 py-2 text-primary-foreground" :to="{ name: 'host', params: { id: host.id } }">{{ host.hostname }} · View host</RouterLink>
  </div>
</template>
