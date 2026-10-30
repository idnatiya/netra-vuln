<script setup lang="ts">
import { LogOut } from '@lucide/vue'
import { ref } from 'vue'
import { toast } from 'vue-sonner'
import PageHeader from '@/presentation/components/PageHeader.vue'
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/presentation/components/ui/alert-dialog'
import { Button } from '@/presentation/components/ui/button'
import { Input } from '@/presentation/components/ui/input'
import { useBreadcrumbs } from '@/presentation/composables/breadcrumbs'
import { useAdminSessions, useChangePassword, useRevokeSession } from '@/presentation/composables/queries'
import { session } from '@/presentation/composables/session'
import { describeUserAgent, errorMessage, formatDateTime, plural, relative } from '@/presentation/lib/format'

useBreadcrumbs(() => [{ label: 'Settings' }, { label: 'Account' }])

const sessions = useAdminSessions()
const changePassword = useChangePassword()
const revoke = useRevokeSession()

const current = ref('')
const next = ref('')
const confirm = ref('')

async function savePassword() {
  try {
    const n = await changePassword.mutateAsync({ current: current.value, next: next.value, confirm: confirm.value })
    current.value = next.value = confirm.value = ''
    toast.success(n ? `Password changed. ${plural(n, 'other session')} signed out.` : 'Password changed.')
  } catch (e) {
    toast.error(errorMessage(e))
  }
}

// The dialog closes before the action's click handler runs, so the target is
// kept apart from the open state.
const target = ref<{ id?: number, label: string }>({ label: '' })
const confirming = ref(false)
function ask(t: { id?: number, label: string }) {
  target.value = t
  confirming.value = true
}
async function confirmRevoke() {
  const { id } = target.value
  try {
    await revoke.mutateAsync(id)
    toast.success(id === undefined ? 'Other sessions signed out.' : 'Session signed out.')
  } catch (e) {
    toast.error(errorMessage(e))
  }
}
const others = () => (sessions.data.value ?? []).filter((s) => !s.current).length
const row = 'grid grid-cols-1 gap-2 border-b px-4 py-4 last:border-b-0 md:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] md:items-center md:gap-6'
</script>

<template>
  <PageHeader title="Account" description="Your admin account on this central." />

  <div class="grid max-w-4xl grid-cols-1 gap-6">
    <section class="overflow-hidden rounded-md border bg-card">
      <h2 class="micro-cap border-b bg-muted px-4 py-2.5 text-muted-foreground">Profile</h2>
      <div :class="row">
        <div><p class="font-medium">Username</p><p class="mt-0.5 text-[13px] text-muted-foreground">Set on the server with <code>central admin create</code>.</p></div>
        <div class="flex h-10 items-center rounded-md border border-input bg-muted/40 px-3 text-muted-foreground">{{ session?.username }}</div>
      </div>
      <div :class="row">
        <div><p class="font-medium">Role</p><p class="mt-0.5 text-[13px] text-muted-foreground">Every admin sees all clients.</p></div>
        <div class="flex h-10 items-center rounded-md border border-input bg-muted/40 px-3 text-muted-foreground">Admin</div>
      </div>
    </section>

    <form class="overflow-hidden rounded-md border bg-card" @submit.prevent="savePassword">
      <h2 class="micro-cap border-b bg-muted px-4 py-2.5 text-muted-foreground">Password</h2>
      <input type="text" autocomplete="username" :value="session?.username" hidden>
      <label :class="row">
        <span class="font-medium">Current password</span>
        <Input v-model="current" type="password" autocomplete="current-password" class="h-10" required />
      </label>
      <label :class="row">
        <span><span class="block font-medium">New password</span><span class="mt-0.5 block text-[13px] text-muted-foreground">12 to 72 characters.</span></span>
        <Input v-model="next" type="password" autocomplete="new-password" class="h-10" required minlength="12" maxlength="72" />
      </label>
      <label :class="row">
        <span class="font-medium">Confirm new password</span>
        <Input v-model="confirm" type="password" autocomplete="new-password" class="h-10" required />
      </label>
      <div class="flex flex-wrap items-center justify-end gap-3 border-t bg-muted/40 px-4 py-3">
        <p class="mr-auto text-[13px] text-muted-foreground">Your other sessions are signed out when the password changes.</p>
        <Button type="submit" :disabled="changePassword.isPending.value">Change password</Button>
      </div>
    </form>

    <section class="overflow-hidden rounded-md border bg-card">
      <div class="flex items-center justify-between gap-3 border-b bg-muted px-4 py-2.5">
        <h2 class="micro-cap text-muted-foreground">Sessions</h2>
        <Button size="sm" variant="outline" :disabled="!others()" @click="ask({ label: plural(others(), 'other session') })">
          Sign out other sessions
        </Button>
      </div>
      <p v-if="sessions.isError.value" class="px-4 py-6 text-destructive">{{ sessions.error.value?.message }}</p>
      <div class="overflow-x-auto">
        <table class="w-full min-w-[640px] whitespace-nowrap">
          <thead class="micro-cap border-b text-left text-muted-foreground">
            <tr><th class="px-4 py-2 font-semibold">Device</th><th class="px-4 py-2 font-semibold">IP</th><th class="px-4 py-2 font-semibold">Signed in</th><th class="px-4 py-2 font-semibold">Expires</th><th /></tr>
          </thead>
          <tbody class="divide-y">
            <tr v-for="s in sessions.data.value ?? []" :key="s.id">
              <td class="px-4 py-3">
                <span class="font-medium" :title="s.userAgent">{{ describeUserAgent(s.userAgent) }}</span>
                <span v-if="s.current" class="micro-cap ml-2 rounded-[4px] bg-gold px-1.5 text-ink">This session</span>
              </td>
              <td class="px-4 py-3 font-mono text-[13px]">{{ s.ip || '—' }}</td>
              <td class="px-4 py-3 text-[13px] text-muted-foreground" :title="formatDateTime(s.createdAt)">{{ relative(s.createdAt) }}</td>
              <td class="px-4 py-3 text-[13px] text-muted-foreground" :title="formatDateTime(s.expiresAt)">{{ relative(s.expiresAt) }}</td>
              <td class="px-4 py-3 text-right">
                <button
                  v-if="!s.current" type="button" class="inline-flex items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground"
                  @click="ask({ id: s.id, label: describeUserAgent(s.userAgent) })"
                ><LogOut class="size-3.5" /> Sign out</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
    <p class="text-[13px] text-muted-foreground">Sessions last 12 hours.</p>
  </div>

  <AlertDialog v-model:open="confirming">
    <AlertDialogContent>
      <AlertDialogHeader>
        <AlertDialogTitle>Sign out {{ target.label }}?</AlertDialogTitle>
        <AlertDialogDescription>That device has to sign in again to use central. This session stays signed in.</AlertDialogDescription>
      </AlertDialogHeader>
      <AlertDialogFooter>
        <AlertDialogCancel>Cancel</AlertDialogCancel>
        <AlertDialogAction :disabled="revoke.isPending.value" @click="confirmRevoke">Sign out</AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
