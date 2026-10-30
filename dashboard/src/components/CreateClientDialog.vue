<script setup lang="ts">
import { ref } from 'vue'
import { toast } from 'vue-sonner'
import { useCreateClient } from '@/composables/queries'
import { errorMessage } from '@/lib/format'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Input } from './ui/input'
import { Label } from './ui/label'

const open = defineModel<boolean>('open', { required: true })
const name = ref('')
const created = ref<{ name: string } | null>(null)
const create = useCreateClient()

async function submit() {
  try {
    created.value = await create.mutateAsync(name.value)
  } catch (e) {
    toast.error(errorMessage(e))
  }
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
          <DialogDescription>Creates a client for its agents and findings.</DialogDescription>
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
          <DialogDescription>Create a single-use token when adding each agent.</DialogDescription>
        </DialogHeader>
        <RouterLink :to="{ name: 'add-agent', query: { client: created.name } }" class="underline" @click="onOpenChange(false)">Add agent</RouterLink>
        <DialogFooter>
          <Button @click="onOpenChange(false)">Done</Button>
        </DialogFooter>
      </template>
    </DialogContent>
  </Dialog>
</template>
