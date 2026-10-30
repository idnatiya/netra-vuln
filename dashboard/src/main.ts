import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createApp } from 'vue'
import { UnauthorizedError } from '@/apis/errors'
import { api, setUnauthorizedHandler } from '@/apis'
import { session } from '@/composables/session'
import { createAppRouter } from '@/router'
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
const router = createAppRouter(api)
setUnauthorizedHandler(() => {
  session.value = null
  queryClient.clear()
  const current = router.currentRoute.value
  if (current.name !== 'login') router.push({ name: 'login', query: { next: current.fullPath } })
})

createApp(App).use(router).use(VueQueryPlugin, { queryClient }).mount('#app')
