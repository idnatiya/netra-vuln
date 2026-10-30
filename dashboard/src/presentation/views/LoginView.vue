<script setup lang="ts">
import { CircleAlert, ShieldCheck } from '@lucide/vue'
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UnauthorizedError } from '@/application/errors'
import { session } from '@/presentation/composables/session'
import { useUseCases } from '@/presentation/composables/useUseCases'
import { errorMessage } from '@/presentation/lib/format'
import { Input } from '@/presentation/components/ui/input'
import { Label } from '@/presentation/components/ui/label'

const uc = useUseCases()
const route = useRoute()
const router = useRouter()
const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  error.value = ''
  busy.value = true
  try {
    session.value = await uc.login(username.value, password.value)
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') ? route.query.next : '/'
    router.replace(next)
  } catch (e) {
    error.value = e instanceof UnauthorizedError ? 'wrong username or password' : errorMessage(e)
  } finally {
    busy.value = false
    password.value = ''
  }
}
</script>

<template>
  <div class="mx-auto grid min-h-svh max-w-[1152px] grid-cols-1 items-center gap-12 px-6 py-10 lg:grid-cols-[1.2fr_1fr] lg:px-12">
    <div class="hidden space-y-8 lg:block">
      <p class="flex items-center gap-2 font-semibold"><ShieldCheck class="size-5" /> netra-vuln</p>
      <h1 class="font-display text-5xl leading-[1.15] font-medium">
        Every client VM's <span class="rounded-[4px] bg-gold px-3 text-ink">critical</span> CVEs in one place.
      </h1>
      <p class="max-w-lg leading-loose text-muted-foreground">
        Agents on each VM run Trivy daily and push the results here. Central never connects to a VM.
      </p>
    </div>

    <div class="mx-auto w-full max-w-sm space-y-6 rounded-xl border bg-card p-8">
      <p class="flex items-center gap-2 font-semibold lg:hidden"><ShieldCheck class="size-5" /> netra-vuln</p>
      <div class="space-y-1">
        <h2 class="text-2xl font-medium">Sign in</h2>
        <p class="text-sm text-muted-foreground">Use the admin account created with <code class="text-foreground">central admin create</code>.</p>
      </div>

      <div v-if="error" role="alert" class="flex items-center gap-2 rounded-md border-l-4 border-sev-critical bg-muted px-3 py-2 text-sm">
        <CircleAlert class="size-4 shrink-0 text-sev-critical" />
        {{ error === 'unauthorized' ? 'Wrong username or password.' : error }}
      </div>

      <form class="space-y-4" @submit.prevent="submit">
        <div class="grid gap-1.5">
          <Label for="username">Username</Label>
          <Input id="username" v-model="username" class="h-11" autocomplete="username" autofocus required />
        </div>
        <div class="grid gap-1.5">
          <Label for="password">Password</Label>
          <Input id="password" v-model="password" class="h-11" type="password" autocomplete="current-password" required />
        </div>
        <button
          type="submit"
          :disabled="busy"
          class="btn-cap mt-2 h-11 w-full rounded-md bg-primary px-4 text-primary-foreground hover:bg-brand disabled:opacity-50"
        >
          Sign in
        </button>
      </form>

      <p class="border-t pt-4 text-[13px] text-muted-foreground">Sessions last 12 hours.</p>
    </div>
  </div>
</template>
