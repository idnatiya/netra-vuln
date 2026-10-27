import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

/** The global client filter lives in the URL (?client=), so links and reloads keep it. */
export function useClientFilter() {
  const route = useRoute()
  const router = useRouter()
  const client = computed<string | undefined>({
    get: () => (typeof route.query.client === 'string' && route.query.client) || undefined,
    set: (v) => {
      router.replace({ query: { ...route.query, client: v || undefined } })
    },
  })
  return { client }
}
