import type {
  AdminSession, Client, Component, ComponentKind, Finding, Host, ScanConfig, Session, Severity, TrendPoint, TriageStatus,
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


export interface HostDTO {
  id: number, client: string, hostname: string, os_family: string, os_name: string, os_version: string,
  arch: string, kernel_running: string, agent_version: string, trivy_version: string, reboot_required: boolean,
  auto_update_enabled: boolean, last_heartbeat_at: string | null, last_scan_at: string | null,
  last_scan_status: 'ok' | 'error' | '', last_ok_scan_at: string | null, created_at: string,
  revoked_at: string | null, open_critical: number, open_high: number, accepted: number,
  false_positive: number, stale_scan: boolean, stale_heartbeat: boolean, new_in_last_scan: number,
  resolved_in_last_scan: number, first_scan: boolean
}
export const toHost = (d: HostDTO): Host => ({
  id: d.id, client: d.client, hostname: d.hostname, osFamily: d.os_family, osName: d.os_name,
  osVersion: d.os_version, arch: d.arch, kernelRunning: d.kernel_running, agentVersion: d.agent_version,
  trivyVersion: d.trivy_version, rebootRequired: d.reboot_required, autoUpdateEnabled: d.auto_update_enabled,
  lastHeartbeatAt: maybeDate(d.last_heartbeat_at), lastScanAt: maybeDate(d.last_scan_at),
  lastScanStatus: d.last_scan_status, lastOkScanAt: maybeDate(d.last_ok_scan_at), createdAt: date(d.created_at),
  revokedAt: maybeDate(d.revoked_at), openCritical: d.open_critical, openHigh: d.open_high,
  accepted: d.accepted, falsePositive: d.false_positive, staleScan: d.stale_scan, staleHeartbeat: d.stale_heartbeat,
  newInLastScan: d.new_in_last_scan, resolvedInLastScan: d.resolved_in_last_scan, firstScan: d.first_scan,
})

export interface FindingDTO {
  id: number, host_id: number, client: string, hostname: string, target: string, type: string, cve: string,
  pkg: string, pkg_path: string, component_kind: ComponentKind, component: string, installed_version: string,
  fixed_version: string, severity: Severity, title: string, status: TriageStatus, note: string, first_seen: string,
  last_seen: string, resolved_at: string | null
}
export const toFinding = (d: FindingDTO): Finding => ({
  id: d.id, hostId: d.host_id, client: d.client, hostname: d.hostname, target: d.target, type: d.type,
  cve: d.cve, pkg: d.pkg, pkgPath: d.pkg_path, componentKind: d.component_kind, component: d.component,
  installedVersion: d.installed_version, fixedVersion: d.fixed_version,
  severity: d.severity, title: d.title, status: d.status, note: d.note, firstSeen: date(d.first_seen),
  lastSeen: date(d.last_seen), resolvedAt: maybeDate(d.resolved_at),
})

export interface ComponentDTO {
  host_id: number, client: string, hostname: string, kind: ComponentKind, key: string, packages: string[], types: string[],
  pkg_count: number, findings: number, cves: number, critical: number, high: number, first_seen: string
}
export const toComponent = (d: ComponentDTO): Component => ({
  hostId: d.host_id, client: d.client, hostname: d.hostname, kind: d.kind, key: d.key, packages: d.packages, types: d.types,
  pkgCount: d.pkg_count, findings: d.findings, cves: d.cves, critical: d.critical, high: d.high,
  firstSeen: date(d.first_seen),
})

export interface PageDTO<T> { items: T[], total: number, page: number, page_size: number }


export interface TrendDTO { day: string, critical: number, high: number }
// "2026-10-30" is a calendar day; parse it as local midnight, not UTC.
export const toTrend = (d: TrendDTO): TrendPoint => ({ day: new Date(`${d.day}T00:00:00`), critical: d.critical, high: d.high })

export interface AdminSessionDTO { id: number, created_at: string, expires_at: string, ip: string, user_agent: string, current: boolean }
export const toAdminSession = (d: AdminSessionDTO): AdminSession => ({
  id: d.id, createdAt: date(d.created_at), expiresAt: date(d.expires_at), ip: d.ip, userAgent: d.user_agent, current: d.current,
})
