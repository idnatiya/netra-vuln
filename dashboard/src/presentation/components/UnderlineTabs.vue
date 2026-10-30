<script setup lang="ts" generic="T extends string">
defineProps<{ tabs: { value: T, label: string, count?: number }[] }>()
const model = defineModel<T>({ required: true })
</script>

<template>
  <div class="flex gap-6 overflow-x-auto border-b" role="tablist">
    <button
      v-for="t in tabs"
      :key="t.value"
      type="button"
      role="tab"
      :aria-selected="model === t.value"
      class="-mb-px border-b-2 pb-2 whitespace-nowrap"
      :class="model === t.value ? 'border-foreground font-medium' : 'border-transparent text-muted-foreground hover:text-foreground'"
      @click="model = t.value"
    >
      {{ t.label }}
      <span v-if="t.count !== undefined" class="ml-1.5 rounded-full bg-muted px-1.5 text-[13px] text-muted-foreground">{{ t.count }}</span>
    </button>
  </div>
</template>
