<script setup lang="ts">
import { Check, Copy, TriangleAlert } from '@lucide/vue'
import { ref } from 'vue'
import { toast } from 'vue-sonner'
import { useCreateClient } from '@/presentation/composables/queries'
import { errorMessage } from '@/presentation/lib/format'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Input } from './ui/input'
import { Label } from './ui/label'

const open = defineModel<boolean>('open', { required: true })
const name = ref('')
const created = ref<{ name: string, enrollToken: string } | null>(null)
const copied = ref(false)
const create = useCreateClient()

async function submit() {
  try {
    created.value = await create.mutateAsync(name.value)
  } catch (e) {
    toast.error(errorMessage(e))
  }
}

async function copy() {
  if (!created.value) return
  await navigator.clipboard.writeText(created.value.enrollToken)
  copied.value = true
  setTimeout(() => (copied.value = false), 2000)
}

function onOpenChange(o: boolean) {
  open.value = o
  if (!o) {
    // Forget the token as soon as the dialog closes; it is never shown again.
    name.value = ''
    created.value = null
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="onOpenChange">
    <DialogContent class="sm:max-w-lg">
      <template v-if="!created">
        <DialogHeader>
          <DialogTitle>New client</DialogTitle>
          <DialogDescription>Creates the client and its enroll token for installing agents.</DialogDescription>
        </DialogHeader>
        <form class="grid gap-2" @submit.prevent="submit">
          <Label for="client-name">Name</Label>
          <Input id="client-name" v-model="name" placeholder="acme" autocomplete="off" autofocus />
          <p class="text-xs text-muted-foreground">Lowercase letters, digits, "_" and "-". Used as <code>client_id</code> in the agent config.</p>
        </form>
        <DialogFooter>
          <Button variant="outline" @click="onOpenChange(false)">Cancel</Button>
          <Button :disabled="!name || create.isPending.value" @click="submit">Create</Button>
        </DialogFooter>
      </template>

      <template v-else>
        <DialogHeader>
          <DialogTitle>Client "{{ created.name }}" created</DialogTitle>
          <DialogDescription>Copy the enroll token now. It is stored only as a hash and cannot be shown again.</DialogDescription>
        </DialogHeader>
        <div class="flex min-w-0 items-center gap-2 rounded-md border bg-muted/40 p-2">
          <code class="min-w-0 flex-1 break-all font-mono text-xs">{{ created.enrollToken }}</code>
          <Button size="icon" variant="ghost" :aria-label="copied ? 'Copied' : 'Copy token'" @click="copy">
            <Check v-if="copied" class="size-4 text-ok" />
            <Copy v-else class="size-4" />
          </Button>
        </div>
        <div class="flex gap-2 text-xs text-muted-foreground">
          <TriangleAlert class="size-4 shrink-0 text-sev-medium" />
          <p>
            Put it in Ansible Vault as the client's <code>vuln_agent_enroll_token</code>, or pass it to
            <code>vuln-agent enroll</code> via <code>VULN_AGENT_ENROLL_TOKEN</code>.
          </p>
        </div>
        <DialogFooter>
          <Button @click="onOpenChange(false)">Done</Button>
        </DialogFooter>
      </template>
    </DialogContent>
  </Dialog>
</template>
