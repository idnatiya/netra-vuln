import type {
  Client, Count, CVEAge, Finding, Host, Overview, ScanConfig, Session, Severity, TrendPoint, TriageStatus,
} from '@/domain/models'

// Shapes returned by central's admin API (snake_case) and their mapping to domain types.

const date = (s: string) => new Date(s)
const maybeDate = (s: string | null) => (s ? new Date(s) : null)

export interface SessionDTO { username: string, expires_at: string }
export const toSession = (d: SessionDTO): Session => ({ username: d.username, expiresAt: date(d.expires_at) })

export interface ClientDTO {
  name: string, scan_config: ScanConfig | null, created_at: string, hosts: number, open_critical: number, open_high: number
}
export const toClient = (d: ClientDTO): Client => ({
  name: d.name, scanConfig: d.scan_config, createdAt: date(d.created_at), hosts: d.hosts,
  openCritical: d.open_critical, openHigh: d.open_high,
})

export interface OverviewDTO {
  totals: {
    clients: number, hosts: number, open_critical: number, open_high: number, accepted: number,
    false_positive: number, stale_hosts: number, reboot_required: number, auto_update_off: number
  }
  clients: ClientDTO[]
}
export const toOverview = (d: OverviewDTO): Overview => ({
  totals: {
    clients: d.totals.clients, hosts: d.totals.hosts, openCritical: d.totals.open_critical,
    openHigh: d.totals.open_high, accepted: d.totals.accepted, falsePositive: d.totals.false_positive,
    staleHosts: d.totals.stale_hosts, rebootRequired: d.totals.reboot_required, autoUpdateOff: d.totals.auto_update_off,
  },
  clients: d.clients.map(toClient),
})

export interface HostDTO {
  id: number, client: string, hostname: string, os_family: string, os_name: string, os_version: string,
  arch: string, kernel_running: string, agent_version: string, trivy_version: string, reboot_required: boolean,
  auto_update_enabled: boolean, last_heartbeat_at: string | null, last_scan_at: string | null,
  last_scan_status: 'ok' | 'error' | '', last_ok_scan_at: string | null, created_at: string,
  revoked_at: string | null, open_critical: number, open_high: number, accepted: number,
  false_positive: number, stale_scan: boolean, stale_heartbeat: boolean
}
export const toHost = (d: HostDTO): Host => ({
  id: d.id, client: d.client, hostname: d.hostname, osFamily: d.os_family, osName: d.os_name,
  osVersion: d.os_version, arch: d.arch, kernelRunning: d.kernel_running, agentVersion: d.agent_version,
  trivyVersion: d.trivy_version, rebootRequired: d.reboot_required, autoUpdateEnabled: d.auto_update_enabled,
  lastHeartbeatAt: maybeDate(d.last_heartbeat_at), lastScanAt: maybeDate(d.last_scan_at),
  lastScanStatus: d.last_scan_status, lastOkScanAt: maybeDate(d.last_ok_scan_at), createdAt: date(d.created_at),
  revokedAt: maybeDate(d.revoked_at), openCritical: d.open_critical, openHigh: d.open_high,
  accepted: d.accepted, falsePositive: d.false_positive, staleScan: d.stale_scan, staleHeartbeat: d.stale_heartbeat,
})

export interface FindingDTO {
  id: number, host_id: number, client: string, hostname: string, target: string, type: string, cve: string,
  pkg: string, installed_version: string, fixed_version: string, severity: Severity, title: string,
  status: TriageStatus, note: string, first_seen: string, last_seen: string, resolved_at: string | null
}
export const toFinding = (d: FindingDTO): Finding => ({
  id: d.id, hostId: d.host_id, client: d.client, hostname: d.hostname, target: d.target, type: d.type,
  cve: d.cve, pkg: d.pkg, installedVersion: d.installed_version, fixedVersion: d.fixed_version,
  severity: d.severity, title: d.title, status: d.status, note: d.note, firstSeen: date(d.first_seen),
  lastSeen: date(d.last_seen), resolvedAt: maybeDate(d.resolved_at),
})

export interface PageDTO<T> { items: T[], total: number, page: number, page_size: number }

export interface TrendDTO { day: string, critical: number, high: number }
export const toTrend = (d: TrendDTO): TrendPoint => ({ day: date(`${d.day}T00:00:00Z`), critical: d.critical, high: d.high })

export interface CVEAgeDTO { cve: string, severity: Severity, title: string, first_seen: string, hosts: number }
export const toCVEAge = (d: CVEAgeDTO): CVEAge => ({
  cve: d.cve, severity: d.severity, title: d.title, firstSeen: date(d.first_seen), hosts: d.hosts,
})

export interface DistributionDTO { os: Count[], agent_versions: Count[], trivy_versions: Count[] }
