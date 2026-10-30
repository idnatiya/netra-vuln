<script setup lang="ts" generic="T extends string">
import { Check, ChevronDown } from '@lucide/vue'
import type { Component } from 'vue'
import { computed } from 'vue'
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from '@/presentation/components/ui/dropdown-menu'

// One segment of a joined filter bar (put several inside FilterBar): an icon,
// the current choice, and a menu of options.
const props = defineProps<{ icon: Component, options: { value: T, label: string }[], label: string }>()
const model = defineModel<T>({ required: true })
const current = computed(() => props.options.find((o) => o.value === model.value)?.label ?? props.label)
</script>

<template>
  <DropdownMenu>
    <DropdownMenuTrigger
      :aria-label="label"
      class="inline-flex h-9 items-center gap-2 px-3 font-medium outline-none hover:bg-muted focus-visible:bg-muted data-[state=open]:bg-muted"
    >
      <component :is="icon" class="size-4 text-muted-foreground" />
      <span class="max-w-40 truncate">{{ current }}</span>
      <ChevronDown class="size-3.5 text-muted-foreground" />
    </DropdownMenuTrigger>
    <DropdownMenuContent align="start" class="max-h-80 min-w-44 overflow-y-auto">
      <DropdownMenuItem v-for="o in options" :key="o.value" @select="model = o.value">
        <Check class="size-4" :class="o.value === model ? 'opacity-100' : 'opacity-0'" />
        {{ o.label }}
      </DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>
</template>
