// Domain types for the admin dashboard. Pure TypeScript: no Vue, no HTTP.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const
export type Severity = (typeof SEVERITIES)[number]

export const TRIAGE_STATUSES = ['open', 'accepted', 'false_positive'] as const
export type TriageStatus = (typeof TRIAGE_STATUSES)[number]

export interface Session {
  username: string
  expiresAt: Date
}

export interface Totals {
  clients: number
  hosts: number
  openCritical: number
  openHigh: number
  accepted: number
  falsePositive: number
  staleHosts: number
  rebootRequired: number
  autoUpdateOff: number
}

export interface ScanConfig {
  severity?: Severity[]
  ignore_unfixed?: boolean
  skip_dirs?: string[]
  timeout?: string
}

export interface Client {
  name: string
  scanConfig: ScanConfig | null // null = agent defaults
  createdAt: Date
  hosts: number
  openCritical: number
  openHigh: number
}

export interface Overview {
  totals: Totals
  clients: Client[]
}

export interface Host {
  id: number
  client: string
  hostname: string
  osFamily: string
  osName: string
  osVersion: string
  arch: string
  kernelRunning: string
  agentVersion: string
  trivyVersion: string
  rebootRequired: boolean
  autoUpdateEnabled: boolean
  lastHeartbeatAt: Date | null
  lastScanAt: Date | null
  lastScanStatus: 'ok' | 'error' | ''
  lastOkScanAt: Date | null
  createdAt: Date
  revokedAt: Date | null
  openCritical: number
  openHigh: number
  accepted: number
  falsePositive: number
  staleScan: boolean
  staleHeartbeat: boolean
}

export interface Finding {
  id: number
  hostId: number
  client: string
  hostname: string
  target: string
  type: string
  cve: string
  pkg: string
  installedVersion: string
  fixedVersion: string
  severity: Severity
  title: string
  status: TriageStatus
  note: string
  firstSeen: Date
  lastSeen: Date
  resolvedAt: Date | null
}

export type FindingSort = 'severity' | 'first_seen' | 'last_seen'

export interface FindingFilter {
  client?: string
  hostId?: number
  severity?: Severity
  status?: TriageStatus
  query?: string
  includeResolved?: boolean
  sort?: FindingSort
  page: number
  pageSize: number
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

export interface TrendPoint {
  day: Date
  critical: number
  high: number
}

export interface CVEAge {
  cve: string
  severity: Severity
  title: string
  firstSeen: Date
  hosts: number
}

export interface Count {
  key: string
  n: number
}

export interface Distribution {
  os: Count[]
  agentVersions: Count[]
  trivyVersions: Count[]
}
