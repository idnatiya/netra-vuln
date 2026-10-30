<script setup lang="ts">
import { ChevronRight } from '@lucide/vue'
import { computed, ref } from 'vue'
import type { Component, ComponentKind, Finding, Host, TriageStatus } from '@/types/models'
import { componentAdvice } from '@/lib/rules'
import { plural } from '@/lib/format'
import ComponentFindings from './ComponentFindings.vue'
import CopyCommand from './CopyCommand.vue'
import CountCell from './CountCell.vue'
import LevelStripe from './LevelStripe.vue'
import { Button } from './ui/button'

const props = defineProps<{ component: Component, host: Host, status: TriageStatus, grid: string }>()
defineEmits<{ triage: [c: Component, title: string], triageFinding: [f: Finding] }>()

const open = ref(false)
const advice = computed(() => componentAdvice(props.component, props.host))
const kindLabel: Record<ComponentKind, string> = { os: 'OS packages', app: 'Application', binary: 'Binary' }
const level = computed(() => (props.component.critical > 0 ? 'critical' : props.component.high > 0 ? 'high' : 'none'))
</script>

<template>
  <article class="relative border-b last:border-b-0">
    <LevelStripe :level="level" />
    <button
      type="button"
      :class="[grid, 'w-full px-4 py-3.5 text-left hover:bg-muted/40']"
      :aria-expanded="open"
      @click="open = !open"
    >
      <div class="flex min-w-0 items-start gap-2">
        <ChevronRight class="mt-1 size-4 shrink-0 text-muted-foreground transition-transform" :class="open && 'rotate-90'" />
        <div class="min-w-0">
          <p class="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span class="font-semibold">{{ advice.title }}</span>
            <span class="rounded-sm bg-muted px-1.5 text-[13px] text-muted-foreground">
              {{ advice.kernel === 'running' ? 'running' : advice.kernel === 'standby' ? 'not running' : kindLabel[component.kind] }}
            </span>
          </p>
          <p class="mt-0.5 truncate text-[13px] text-muted-foreground" :title="advice.detail">
            {{ advice.detail }} · {{ plural(component.cves, 'CVE') }}
          </p>
        </div>
      </div>
      <div class="text-right"><CountCell :value="component.critical" /></div>
      <div class="text-right"><CountCell :value="component.high" /></div>
    </button>

    <div v-if="open" class="grid grid-cols-1 gap-3 px-4 pb-4 sm:pl-10">
      <p>{{ advice.note }}</p>
      <CopyCommand v-if="advice.command" :command="advice.command" />
      <div class="flex flex-wrap items-center gap-3">
        <Button variant="outline" @click="$emit('triage', component, advice.title)">
          {{ status === 'open' ? 'Accept or dismiss all…' : 'Change verdict…' }}
        </Button>
        <span class="min-w-0 flex-1 truncate text-[13px] text-muted-foreground">
          {{ plural(component.pkgCount, 'package') }}: {{ component.packages.join(', ') }}<template v-if="component.pkgCount > component.packages.length">, …</template>
        </span>
      </div>
      <ComponentFindings :component="component" :status="status" @triage="(f) => $emit('triageFinding', f)" />
    </div>
  </article>
</template>
