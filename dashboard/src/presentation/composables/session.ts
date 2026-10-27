import { ref } from 'vue'
import type { Session } from '@/domain/models'

/** The logged-in admin, or null. Set by the router guard and the login view. */
export const session = ref<Session | null>(null)
