import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createApp } from 'vue'
import { UnauthorizedError } from '@/application/errors'
import { buildUseCases, UseCasesKey } from '@/di'
import { session } from '@/presentation/composables/session'
import { createAppRouter } from '@/presentation/router'
import App from './App.vue'
import './style.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: (n, err) => !(err instanceof UnauthorizedError) && n < 2,
    },
  },
})

// The use cases need to send the user to /login on 401, and the router needs the
// use cases for its guard, so the redirect is bound after both exist.
let onUnauthorized = () => {}
const uc = buildUseCases(() => onUnauthorized())
const router = createAppRouter(uc)
onUnauthorized = () => {
  session.value = null
  queryClient.clear()
  const current = router.currentRoute.value
  if (current.name !== 'login') router.push({ name: 'login', query: { next: current.fullPath } })
}

createApp(App).provide(UseCasesKey, uc).use(router).use(VueQueryPlugin, { queryClient }).mount('#app')
