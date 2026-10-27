import type { Repositories } from '@/application/ports'
import type { ComponentFilter, ScanConfig } from '@/domain/models'
import {
  type ClientDTO, type ComponentDTO, type CVEAgeDTO, type DistributionDTO, type FindingDTO, type HostDTO, type OverviewDTO,
  type PageDTO, type SessionDTO, type TrendDTO,
  toClient, toComponent, toCVEAge, toFinding, toHost, toOverview, toSession, toTrend,
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
    },
    stats: {
      overview: async (client) => toOverview(await http.get<OverviewDTO>('/overview', { client })),
      trend: async (client, days) => (await http.get<TrendDTO[]>('/trend', { client, days })).map(toTrend),
      oldestCVEs: async (client, limit) => (await http.get<CVEAgeDTO[]>('/oldest-cves', { client, limit })).map(toCVEAge),
      distribution: async () => {
        const d = await http.get<DistributionDTO>('/distribution')
        return { os: d.os, agentVersions: d.agent_versions, trivyVersions: d.trivy_versions }
      },
    },
    findings: {
      list: async (f) => {
        const p = await http.get<PageDTO<FindingDTO>>('/findings', {
          ...filterParams(f), sort: f.sort, page: f.page, page_size: f.pageSize,
        })
        return { items: p.items.map(toFinding), total: p.total, page: p.page, pageSize: p.page_size }
      },
      components: async (f) => (await http.get<ComponentDTO[]>('/components', filterParams(f))).map(toComponent),
      triage: (id, status, note) => http.request<void>('PATCH', `/findings/${id}`, { status, note }),
    },
    hosts: {
      list: async (client) => (await http.get<HostDTO[]>('/hosts', { client })).map(toHost),
      revoke: (id) => http.request<void>('POST', `/hosts/${id}/revoke`),
    },
    clients: {
      list: async () => (await http.get<ClientDTO[]>('/clients')).map(toClient),
      create: async (name) => (await http.request<{ enroll_token: string }>('POST', '/clients', { name })).enroll_token,
      setScanConfig: (name, cfg) =>
        http.request<ScanConfig>('PUT', `/clients/${encodeURIComponent(name)}/scan-config`, cfg),
      clearScanConfig: (name) => http.request<void>('DELETE', `/clients/${encodeURIComponent(name)}/scan-config`),
    },
  }
}
