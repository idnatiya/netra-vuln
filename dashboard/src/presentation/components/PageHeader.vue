<script setup lang="ts">
defineProps<{ title: string, description?: string }>()
</script>

<template>
  <div class="flex flex-wrap items-start justify-between gap-4">
    <div class="min-w-0">
      <h1 class="text-[22px] font-semibold">{{ title }}</h1>
      <p v-if="description" class="mt-0.5 text-muted-foreground">{{ description }}</p>
    </div>
    <div v-if="$slots.default" class="flex items-center gap-2"><slot /></div>
  </div>
</template>
