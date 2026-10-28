<script setup lang="ts">
import { ref, watch } from 'vue'
import { toast } from 'vue-sonner'
import type { Component, TriageStatus } from '@/domain/models'
import { triageNeedsNote } from '@/domain/rules'
import { useTriageComponent } from '@/presentation/composables/queries'
import { errorMessage, plural } from '@/presentation/lib/format'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Label } from './ui/label'
import { Textarea } from './ui/textarea'

const props = defineProps<{ component: Component | null, title: string, current: TriageStatus }>()
const emit = defineEmits<{ close: [] }>()

const status = ref<TriageStatus>('accepted')
const note = ref('')
const triage = useTriageComponent()

watch(() => props.component, () => {
  status.value = props.current === 'open' ? 'accepted' : 'open'
  note.value = ''
})

const options: { value: TriageStatus, title: string, help: string }[] = [
  { value: 'accepted', title: 'Accept risk', help: 'Known and tolerated, e.g. a dev cache or a fallback kernel.' },
  { value: 'false_positive', title: 'False positive', help: 'Not applicable to this host.' },
  { value: 'open', title: 'Reopen', help: 'Count these findings as open again.' },
]

async function save() {
  if (!props.component) return
  try {
    const n = await triage.mutateAsync({ component: props.component, status: status.value, note: note.value })
    toast.success(`${plural(n, 'finding')} in ${props.title} updated`)
    emit('close')
  } catch (e) {
    toast.error(errorMessage(e))
  }
}
</script>

<template>
  <Dialog :open="!!component" @update:open="(o) => !o && emit('close')">
    <DialogContent v-if="component" class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle>Triage {{ title }}</DialogTitle>
        <DialogDescription>
          Applies to all {{ plural(component.findings, 'finding') }} in this component on {{ component.hostname }}.
          The verdict stays across re-scans; nothing is deleted.
        </DialogDescription>
      </DialogHeader>

      <fieldset class="grid gap-2">
        <legend class="sr-only">Verdict</legend>
        <label
          v-for="o in options.filter((o) => o.value !== current)"
          :key="o.value"
          class="flex cursor-pointer gap-3 rounded-md border p-3 text-sm has-[:checked]:border-primary has-[:checked]:bg-muted/50"
        >
          <input v-model="status" type="radio" name="component-triage" :value="o.value" class="mt-0.5 accent-primary">
          <span>
            <span class="font-medium">{{ o.title }}</span>
            <span class="block text-muted-foreground">{{ o.help }}</span>
          </span>
        </label>
      </fieldset>

      <div class="grid gap-2">
        <Label for="component-note">Note <span v-if="triageNeedsNote(status)" class="text-muted-foreground">(required)</span></Label>
        <Textarea id="component-note" v-model="note" rows="3" maxlength="2000" placeholder="Why, and until when?" />
      </div>

      <DialogFooter>
        <Button variant="outline" @click="emit('close')">Cancel</Button>
        <Button :disabled="triage.isPending.value" @click="save">Save</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
