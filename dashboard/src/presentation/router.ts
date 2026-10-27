import { createRouter, createWebHistory } from 'vue-router'
import type { UseCases } from '@/application/usecases'
import { session } from './composables/session'

export function createAppRouter(uc: UseCases) {
  const router = createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/login', name: 'login', component: () => import('./views/LoginView.vue'), meta: { public: true } },
      {
        path: '/',
        component: () => import('./layouts/AppLayout.vue'),
        children: [
          { path: '', name: 'overview', component: () => import('./views/OverviewView.vue') },
          { path: 'findings', name: 'findings', component: () => import('./views/FindingsView.vue') },
          { path: 'hosts', name: 'hosts', component: () => import('./views/HostsView.vue') },
          { path: 'clients', name: 'clients', component: () => import('./views/ClientsView.vue') },
        ],
      },
      { path: '/:pathMatch(.*)*', redirect: '/' },
    ],
  })

  router.beforeEach(async (to) => {
    if (to.meta.public || session.value) return true
    try {
      session.value = await uc.currentSession()
      return true
    } catch {
      return { name: 'login', query: { next: to.fullPath } }
    }
  })
  return router
}
