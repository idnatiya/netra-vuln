<script setup lang="ts">
import { Check, Copy } from '@lucide/vue'
import { ref } from 'vue'
import { toast } from 'vue-sonner'
import { Button } from './ui/button'

const props = defineProps<{ command: string }>()
const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.command)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    toast.error('Could not copy; select the command instead.')
  }
}
</script>

<template>
  <div class="flex items-start gap-2 rounded-md bg-muted px-3 py-2">
    <code class="min-w-0 flex-1 font-mono text-xs leading-5 break-all select-all">{{ command }}</code>
    <Button size="icon-sm" variant="ghost" class="-my-1 shrink-0" :aria-label="copied ? 'Copied' : 'Copy command'" @click="copy">
      <Check v-if="copied" class="text-ok" /><Copy v-else />
    </Button>
  </div>
</template>
