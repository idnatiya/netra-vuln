<script setup lang="ts">
import { ChevronRight } from '@lucide/vue'
import { computed, ref } from 'vue'
import type { Component, ComponentKind, Finding, Host, TriageStatus } from '@/domain/models'
import { componentAdvice } from '@/domain/rules'
import { formatNumber, plural } from '@/presentation/lib/format'
import ComponentFindings from './ComponentFindings.vue'
import CopyCommand from './CopyCommand.vue'
import { Button } from './ui/button'

const props = defineProps<{ component: Component, host: Host, status: TriageStatus }>()
defineEmits<{ triage: [c: Component, title: string], triageFinding: [f: Finding] }>()

const open = ref(false)
const advice = computed(() => componentAdvice(props.component, props.host))
const kindLabel: Record<ComponentKind, string> = { os: 'OS packages', app: 'Application', binary: 'Binary' }
</script>

<template>
  <article class="rounded-lg border bg-background">
    <button
      type="button"
      class="flex w-full items-center gap-3 p-4 text-left"
      :aria-expanded="open"
      @click="open = !open"
    >
      <ChevronRight class="size-4 shrink-0 text-muted-foreground transition-transform" :class="open && 'rotate-90'" />
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-baseline gap-x-2">
          <span class="font-medium">{{ advice.title }}</span>
          <span class="text-xs text-muted-foreground">{{ kindLabel[component.kind] }}</span>
          <span v-if="advice.kernel === 'running'" class="text-xs text-sev-high">running</span>
          <span v-else-if="advice.kernel === 'standby'" class="text-xs text-muted-foreground">fallback, not running</span>
        </div>
        <p class="truncate font-mono text-xs text-muted-foreground" :title="advice.detail">{{ advice.detail }}</p>
      </div>
      <div class="flex shrink-0 items-baseline gap-4 text-sm tabular-nums">
        <span :class="component.critical ? 'font-semibold text-sev-critical' : 'text-muted-foreground'">{{ formatNumber(component.critical) }} <span class="text-xs font-normal">crit</span></span>
        <span :class="component.high ? '' : 'text-muted-foreground'">{{ formatNumber(component.high) }} <span class="text-xs text-muted-foreground">high</span></span>
        <span class="hidden text-muted-foreground sm:inline">{{ plural(component.cves, 'CVE') }}</span>
      </div>
    </button>

    <div v-if="open" class="grid gap-3 border-t px-4 pt-3 pb-4">
      <p class="text-sm">{{ advice.note }}</p>
      <CopyCommand v-if="advice.command" :command="advice.command" />
      <div class="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <span>{{ plural(component.pkgCount, 'package') }}: {{ component.packages.join(', ') }}<template v-if="component.pkgCount > component.packages.length">, …</template></span>
        <Button size="sm" variant="outline" class="ml-auto" @click="$emit('triage', component, advice.title)">
          {{ status === 'open' ? 'Accept or dismiss all…' : 'Change verdict…' }}
        </Button>
      </div>
      <ComponentFindings :component="component" :status="status" @triage="(f) => $emit('triageFinding', f)" />
    </div>
  </article>
</template>
