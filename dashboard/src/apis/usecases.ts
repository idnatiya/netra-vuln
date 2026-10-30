import type { Component, ComponentFilter, FindingFilter, ScanConfig, TrendFilter, TriageStatus } from '@/types/models'
import { isValidClientName, triageNeedsNote } from '@/lib/rules'
import { ApiError } from './errors'
import type { Repositories } from './ports'

// Use cases: validation and orchestration on top of the ports. Views call these only.

/** Trimmed triage note; accepting or dismissing needs one. */
function triageNote(status: TriageStatus, note: string): string {
  const n = note.trim()
  if (triageNeedsNote(status) && !n) throw new ApiError('a note is required when accepting or dismissing a finding', 400)
  if (n.length > 2000) throw new ApiError('note is longer than 2000 characters', 400)
  return n
}

export function createUseCases(r: Repositories) {
  return {
    login: (username: string, password: string) => {
      if (!username || !password) throw new ApiError('username and password are required', 400)
      return r.auth.login(username.trim(), password)
    },
    logout: () => r.auth.logout(),
    currentSession: () => r.auth.me(),
    /** Validates locally (length, confirmation) so typos never reach the server. */
    changePassword: (current: string, next: string, confirm: string) => {
      if (!current) throw new ApiError('enter your current password', 400)
      if (next.length < 12 || next.length > 72) throw new ApiError('the new password must be 12-72 characters', 400)
      if (next !== confirm) throw new ApiError('the new passwords do not match', 400)
      if (next === current) throw new ApiError('the new password must differ from the current one', 400)
      return r.auth.changePassword(current, next)
    },
    listSessions: () => r.auth.sessions(),
    revokeSession: (id: number) => r.auth.revokeSession(id),
    revokeOtherSessions: () => r.auth.revokeOtherSessions(),

    listFindings: (filter: FindingFilter) => r.findings.list({ ...filter, query: filter.query?.trim() || undefined }),
    listComponents: (filter: ComponentFilter) => r.findings.components({ ...filter, query: filter.query?.trim() || undefined }),
    triageFinding: async (id: number, status: TriageStatus, note: string) => {
      await r.findings.triage(id, status, triageNote(status, note))
    },
    triageComponent: (c: Pick<Component, 'hostId' | 'kind' | 'key'>, status: TriageStatus, note: string) =>
      r.findings.triageComponent(c, status, triageNote(status, note)),

    listHosts: (client?: string) => r.hosts.list(client),
    revokeHost: (id: number) => r.hosts.revoke(id),

    trend: (filter: TrendFilter) => r.trend.trend(filter),

    listClients: () => r.clients.list(),
    createClient: async (name: string) => {
      const n = name.trim()
      if (!isValidClientName(n)) {
        throw new ApiError('client name: lowercase letters, digits, "_" or "-", max 64 chars', 400)
      }
      return { name: n, enrollToken: await r.clients.create(n) }
    },
    /** Parses the editor's JSON text; the server validates the values. Empty text clears overrides. */
    saveScanConfig: async (name: string, text: string): Promise<ScanConfig | null> => {
      if (!text.trim()) {
        await r.clients.clearScanConfig(name)
        return null
      }
      let cfg: unknown
      try {
        cfg = JSON.parse(text)
      } catch {
        throw new ApiError('scan config is not valid JSON', 400)
      }
      if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) {
        throw new ApiError('scan config must be a JSON object', 400)
      }
      return r.clients.setScanConfig(name, cfg as ScanConfig)
    },
  }
}

export type UseCases = ReturnType<typeof createUseCases>
