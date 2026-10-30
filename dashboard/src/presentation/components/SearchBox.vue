<script setup lang="ts">
import { Search, X } from '@lucide/vue'

// A search input that also shows the active filters as key:value tokens.
defineProps<{ placeholder: string, tokens?: { key: string, value: string }[] }>()
defineEmits<{ removeToken: [key: string] }>()
const model = defineModel<string>({ required: true })
</script>

<template>
  <div class="flex h-10 items-center gap-2 rounded-md border border-input bg-background px-3 focus-within:ring-2 focus-within:ring-ring">
    <Search class="size-4 shrink-0 text-muted-foreground" />
    <button
      v-for="t in tokens ?? []"
      :key="t.key"
      type="button"
      class="group inline-flex shrink-0 items-center gap-0.5 rounded-sm bg-muted px-1.5 py-0.5 font-mono text-[13px]"
      :title="`Remove ${t.key}:${t.value}`"
      @click="$emit('removeToken', t.key)"
    >
      <span class="text-muted-foreground">{{ t.key }}:</span>{{ t.value }}
      <X class="ml-0.5 size-3 text-muted-foreground group-hover:text-foreground" />
    </button>
    <input
      v-model="model"
      :placeholder="placeholder"
      :aria-label="placeholder"
      class="min-w-0 flex-1 bg-transparent outline-none placeholder:text-muted-foreground"
    >
  </div>
</template>
