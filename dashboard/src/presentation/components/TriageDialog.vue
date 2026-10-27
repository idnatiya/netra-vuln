<script setup lang="ts">
import { ref, watch } from 'vue'
import { toast } from 'vue-sonner'
import { type Finding, TRIAGE_STATUSES, type TriageStatus } from '@/domain/models'
import { triageNeedsNote } from '@/domain/rules'
import { useTriage } from '@/presentation/composables/queries'
import SeverityBadge from './SeverityBadge.vue'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog'
import { Label } from './ui/label'
import { Textarea } from './ui/textarea'
import { errorMessage } from '@/presentation/lib/format'

const props = defineProps<{ finding: Finding | null }>()
const emit = defineEmits<{ close: [] }>()

const status = ref<TriageStatus>('open')
const note = ref('')
const triage = useTriage()

watch(() => props.finding, (f) => {
  status.value = f?.status ?? 'open'
  note.value = f?.note ?? ''
})

const labels: Record<TriageStatus, { title: string, help: string }> = {
  open: { title: 'Open', help: 'Needs a fix. Counts toward the dashboard totals.' },
  accepted: { title: 'Accept risk', help: 'Known and tolerated for now. Kept out of the open totals.' },
  false_positive: { title: 'False positive', help: 'Not applicable to this host. Kept out of the open totals.' },
}

async function save() {
  if (!props.finding) return
  try {
    await triage.mutateAsync({ id: props.finding.id, status: status.value, note: note.value })
    toast.success(`${props.finding.cve} marked ${labels[status.value].title.toLowerCase()}`)
    emit('close')
  } catch (e) {
    toast.error(errorMessage(e))
  }
}
</script>

<template>
  <Dialog :open="!!finding" @update:open="(o) => !o && emit('close')">
    <DialogContent v-if="finding" class="sm:max-w-lg">
      <DialogHeader>
        <DialogTitle class="flex items-center gap-2">
          <SeverityBadge :severity="finding.severity" />
          <span class="font-mono">{{ finding.cve }}</span>
        </DialogTitle>
        <DialogDescription>
          {{ finding.pkg }} {{ finding.installedVersion }} on {{ finding.client }}/{{ finding.hostname }}
        </DialogDescription>
      </DialogHeader>

      <fieldset class="grid gap-2">
        <legend class="mb-2 text-sm font-medium">Verdict</legend>
        <label
          v-for="s in TRIAGE_STATUSES"
          :key="s"
          class="flex cursor-pointer gap-3 rounded-md border p-3 text-sm has-[:checked]:border-primary has-[:checked]:bg-muted/50"
        >
          <input v-model="status" type="radio" name="triage" :value="s" class="mt-0.5 accent-primary">
          <span>
            <span class="font-medium">{{ labels[s].title }}</span>
            <span class="block text-muted-foreground">{{ labels[s].help }}</span>
          </span>
        </label>
      </fieldset>

      <div class="grid gap-2">
        <Label for="triage-note">Note <span v-if="triageNeedsNote(status)" class="text-muted-foreground">(required)</span></Label>
        <Textarea id="triage-note" v-model="note" rows="3" maxlength="2000" placeholder="Why, and until when?" />
      </div>

      <DialogFooter>
        <Button variant="outline" @click="emit('close')">Cancel</Button>
        <Button :disabled="triage.isPending.value" @click="save">Save</Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>
