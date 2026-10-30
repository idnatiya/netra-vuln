<script setup lang="ts">
defineProps<{ name: string }>()
</script>

<template>
  <span class="inline-flex items-center gap-1 rounded-sm bg-muted px-1.5 text-[13px] text-foreground">
    <span class="flex size-3 items-center justify-center rounded-[3px] bg-brand text-[9px] font-semibold">{{ name.charAt(0).toUpperCase() }}</span>
    {{ name }}
  </span>
</template>
