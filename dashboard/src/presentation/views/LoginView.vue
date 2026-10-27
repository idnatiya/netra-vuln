<script setup lang="ts">
import { ShieldCheck } from '@lucide/vue'
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { session } from '@/presentation/composables/session'
import { useUseCases } from '@/presentation/composables/useUseCases'
import { errorMessage } from '@/presentation/lib/format'
import { Button } from '@/presentation/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/presentation/components/ui/card'
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
    error.value = errorMessage(e)
  } finally {
    busy.value = false
    password.value = ''
  }
}
</script>

<template>
  <div class="flex min-h-svh items-center justify-center bg-muted/30 p-4">
    <Card class="w-full max-w-sm">
      <CardHeader>
        <CardTitle class="flex items-center gap-2"><ShieldCheck class="size-5 text-primary" /> Vuln Central</CardTitle>
        <CardDescription>Sign in to the admin dashboard.</CardDescription>
      </CardHeader>
      <CardContent>
        <form class="grid gap-4" @submit.prevent="submit">
          <div class="grid gap-2">
            <Label for="username">Username</Label>
            <Input id="username" v-model="username" autocomplete="username" autofocus required />
          </div>
          <div class="grid gap-2">
            <Label for="password">Password</Label>
            <Input id="password" v-model="password" type="password" autocomplete="current-password" required />
          </div>
          <p v-if="error" role="alert" class="text-sm text-destructive">{{ error === 'unauthorized' ? 'Wrong username or password.' : error }}</p>
          <Button type="submit" :disabled="busy">Sign in</Button>
        </form>
      </CardContent>
    </Card>
  </div>
</template>
