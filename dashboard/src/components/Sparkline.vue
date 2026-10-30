<script setup lang="ts">
import { computed } from 'vue'

// Bar sparkline: one bar per value, scaled to the largest. Zero values draw a
// 2px stub so an empty period still reads as "nothing" rather than "no data".
const props = withDefaults(defineProps<{ values: number[], width?: number, height?: number }>(), { width: 140, height: 28 })

const bars = computed(() => {
  const top = Math.max(...props.values, 1)
  const step = props.width / Math.max(props.values.length, 1)
  return props.values.map((v, i) => {
    const h = Math.max(2, Math.round((v / top) * (props.height - 2)))
    return { x: i * step, y: props.height - h, w: Math.max(1, step - 2), h }
  })
})
</script>

<template>
  <svg :width="width" :height="height" :viewBox="`0 0 ${width} ${height}`" fill="currentColor" aria-hidden="true">
    <rect v-for="(b, i) in bars" :key="i" :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="1" />
  </svg>
</template>
