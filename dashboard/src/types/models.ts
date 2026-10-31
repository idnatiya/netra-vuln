// Domain types for the admin dashboard. Pure TypeScript: no Vue, no HTTP.

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const
export type Severity = (typeof SEVERITIES)[number]

export const TRIAGE_STATUSES = ['open', 'accepted', 'false_positive'] as const
export type TriageStatus = (typeof TRIAGE_STATUSES)[number]

export interface Session {
  username: string
  expiresAt: Date
}

/** One signed-in dashboard session of the current admin. */
export interface AdminSession {
  id: number
  createdAt: Date
  expiresAt: Date
  ip: string
  userAgent: string
  current: boolean
}

/** A Bearer token an AI client uses for the MCP endpoint. */
export interface McpToken {
  id: number
  name: string
  /** Can accept / dismiss / reopen findings, not only read. */
  canTriage: boolean
  createdAt: Date
  lastUsedAt?: Date
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
  /** Findings the last scan opened / resolved; firstScan means nothing to compare against. */
  newInLastScan: number
  resolvedInLastScan: number
  firstScan: boolean
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
  pkgPath: string
  componentKind: ComponentKind
  component: string
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

/** What a group of findings is: OS packages of one source, an app folder, or a binary. */
export type ComponentKind = 'os' | 'app' | 'binary'

/** Findings of one component on one host: one upgrade action. */
export interface Component {
  hostId: number
  client: string
  hostname: string
  kind: ComponentKind
  key: string
  packages: string[]
  /** Trivy result types, e.g. ubuntu, composer-vendor, node-pkg. */
  types: string[]
  pkgCount: number
  findings: number
  cves: number
  critical: number
  high: number
  firstSeen: Date
}

export interface FindingFilter {
  client?: string
  hostId?: number
  severity?: Severity
  status?: TriageStatus
  query?: string
  componentKind?: ComponentKind
  component?: string
  includeResolved?: boolean
  sort?: FindingSort
  page: number
  pageSize: number
}

export type ComponentFilter = Omit<FindingFilter, 'sort' | 'page' | 'pageSize'>

/** Open critical/high on one day (last successful scan of that day, per host). */
export interface TrendPoint {
  day: Date
  critical: number
  high: number
}

export interface TrendFilter {
  client?: string
  hostId?: number
  days: number
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

