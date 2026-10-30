import type { Repositories } from '@/apis/ports'
import type { ComponentFilter, ScanConfig } from '@/types/models'
import {
  type AdminSessionDTO, type ClientDTO, type ComponentDTO, type FindingDTO, type HostDTO, type SessionDTO, type TrendDTO,
  toAdminSession, toClient, toComponent, toFinding, toHost, toSession, toTrend,
} from './dto'
import type { HttpClient } from './http'

// Port implementations backed by central's admin API.

// Query parameters shared by /findings and /components.
const filterParams = (f: ComponentFilter) => ({
  client: f.client, host_id: f.hostId, severity: f.severity, status: f.status, q: f.query,
  component_kind: f.componentKind, component: f.component, include_resolved: f.includeResolved || undefined,
})

export function createHttpRepositories(http: HttpClient): Repositories {
  return {
    auth: {
      login: async (username, password) => toSession(await http.request<SessionDTO>('POST', '/login', { username, password })),
      logout: () => http.request<void>('POST', '/logout'),
      me: async () => toSession(await http.get<SessionDTO>('/me')),
      changePassword: async (current, next) => (await http.request<{ count: number }>('POST', '/me/password', {
        current_password: current, new_password: next,
      })).count,
      sessions: async () => (await http.get<AdminSessionDTO[]>('/me/sessions')).map(toAdminSession),
      revokeSession: (id) => http.request<void>('DELETE', `/me/sessions/${id}`),
      revokeOtherSessions: async () => (await http.request<{ count: number }>('DELETE', '/me/sessions')).count,
    },
    trend: {
      trend: async (f) => (await http.get<TrendDTO[]>('/trend', { client: f.client, host_id: f.hostId, days: f.days })).map(toTrend),
    },
    findings: {
      list: async (f) => {
        const r = await http.page<FindingDTO>('/findings', { ...filterParams(f), sort: f.sort, page: f.page, size: f.pageSize })
        return {
          items: r.data.map(toFinding), total: r.paging?.total_item ?? r.data.length,
          page: r.paging?.page ?? f.page, pageSize: r.paging?.size ?? f.pageSize,
        }
      },
      components: async (f) => (await http.get<ComponentDTO[]>('/components', filterParams(f))).map(toComponent),
      triage: (id, status, note) => http.request<void>('PATCH', `/findings/${id}`, { status, note }),
      triageComponent: async (c, status, note) => (await http.request<{ updated: number }>('POST', '/components/triage', {
        host_id: c.hostId, kind: c.kind, key: c.key, status, note,
      })).updated,
    },
    hosts: {
      list: async (client) => (await http.get<HostDTO[]>('/hosts', { client })).map(toHost),
      revoke: (id) => http.request<void>('POST', `/hosts/${id}/revoke`),
    },
    clients: {
      list: async () => (await http.get<ClientDTO[]>('/clients')).map(toClient),
      create: async (name) => { await http.request('POST', '/clients', { name }) },
      setScanConfig: (name, cfg) =>
        http.request<ScanConfig>('PUT', `/clients/${encodeURIComponent(name)}/scan-config`, cfg),
      clearScanConfig: (name) => http.request<void>('DELETE', `/clients/${encodeURIComponent(name)}/scan-config`),
      issueEnrollToken: async (name) =>
        (await http.request<{ enroll_token: string }>('POST', `/clients/${encodeURIComponent(name)}/enroll-token`)).enroll_token,
      installInfo: async () => {
        const i = await http.get<{ enabled: boolean, public_url: string, agent_version: string }>('/install')
        return { enabled: i.enabled, publicUrl: i.public_url, agentVersion: i.agent_version }
      },
    },
  }
}
