<script setup lang="ts">
import { ref, watch } from 'vue'
import { toast } from 'vue-sonner'
import type { Client } from '@/types/models'
import { useSaveScanConfig } from '@/composables/queries'
import { errorMessage } from '@/lib/format'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Textarea } from './ui/textarea'

const props = defineProps<{ client: Client | null }>()
const emit = defineEmits<{ close: [] }>()
const text = ref('')
const save = useSaveScanConfig()

const example = '{\n  "severity": ["HIGH", "CRITICAL"],\n  "ignore_unfixed": true,\n  "skip_dirs": ["/data/backups"],\n  "timeout": "45m"\n}'

watch(() => props.client, (c) => {
  text.value = c?.scanConfig ? JSON.stringify(c.scanConfig, null, 2) : ''
})

async function submit() {
  if (!props.client) return
  try {
    const cfg = await save.mutateAsync({ name: props.client.name, text: text.value })
    toast.success(cfg ? `Scan config for ${props.client.name} saved` : `${props.client.name} uses agent defaults`)
    emit('close')
  } catch (e) {
    toast.error(errorMessage(e))
  }
}
</script>

<template>
  <Dialog :open="!!client" @update:open="(o) => !o && emit('close')">
    <DialogContent v-if="client" class="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>Scan config: {{ client.name }}</DialogTitle>
        <DialogDescription>
          Overrides sent to this client's agents on their next scan. Only <code>severity</code>,
          <code>ignore_unfixed</code>, <code>skip_dirs</code> and <code>timeout</code> are allowed; leave empty for defaults.
        </DialogDescription>
      </DialogHeader>
      <Textarea v-model="text" rows="10" spellcheck="false" class="font-mono text-xs" :placeholder="example" />
      <p class="text-xs text-muted-foreground">
        Narrowing <code>severity</code> marks out-of-scope findings as resolved on the next scan.
      </p>
      <DialogFooter>
        <Button variant="outline" @click="emit('close')">Cancel</Button>
        <Button :disabled="save.isPending.value" @click="submit">Save</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
