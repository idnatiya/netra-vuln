import { createRouter, createWebHistory } from 'vue-router'
import type { UseCases } from '@/apis/usecases'
import { session } from '../composables/session'

export function createAppRouter(uc: UseCases) {
  const router = createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/login', name: 'login', component: () => import('../pages/LoginView.vue'), meta: { public: true } },
      {
        path: '/',
        component: () => import('../layouts/AppLayout.vue'),
        children: [
          { path: '', name: 'hosts', component: () => import('../pages/HostsView.vue'), meta: { title: 'Hosts' } },
          { path: 'hosts/:id(\\d+)', name: 'host', component: () => import('../pages/HostDetailView.vue'), meta: { title: 'Host' } },
          { path: 'hosts', redirect: '/' },
          { path: 'findings', name: 'findings', component: () => import('../pages/FindingsView.vue'), meta: { title: 'Search CVEs' } },
          { path: 'account', name: 'account', component: () => import('../pages/AccountView.vue'), meta: { title: 'Account' } },
          { path: 'agents/new', name: 'add-agent', component: () => import('../pages/AddAgentView.vue'), meta: { title: 'Add agent' } },
          { path: 'clients', name: 'clients', component: () => import('../pages/ClientsView.vue'), meta: { title: 'Clients' } },
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
