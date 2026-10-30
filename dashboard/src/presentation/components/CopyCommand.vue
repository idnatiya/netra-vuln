<script setup lang="ts">
import { Check, Copy } from '@lucide/vue'
import { ref } from 'vue'
import { toast } from 'vue-sonner'

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
  <!-- Commands keep their line breaks and scroll sideways instead of wrapping. -->
  <div class="flex items-start gap-2 rounded-md bg-sunken px-4 py-3">
    <code class="min-w-0 flex-1 overflow-x-auto font-mono text-[13px] leading-6 whitespace-pre select-all">{{ command }}</code>
    <button
      type="button"
      class="-my-0.5 inline-flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
      :aria-label="copied ? 'Copied' : 'Copy command'"
      @click="copy"
    >
      <Check v-if="copied" class="size-4 text-ok" /><Copy v-else class="size-4" />
    </button>
  </div>
</template>
