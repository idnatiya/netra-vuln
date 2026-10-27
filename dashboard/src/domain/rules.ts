import type { Host, Page, TriageStatus } from './models'

// Pure business rules shared by views. Thresholds mirror central's domain package.

export type HostHealth = 'revoked' | 'stale' | 'attention' | 'healthy'

export function hostHealth(h: Host): HostHealth {
  if (h.revokedAt) return 'revoked'
  if (h.staleScan || h.staleHeartbeat) return 'stale'
  if (h.rebootRequired || !h.autoUpdateEnabled || h.openCritical > 0) return 'attention'
  return 'healthy'
}

/** Human-readable reasons a host needs attention, most urgent first. */
export function hostIssues(h: Host): string[] {
  if (h.revokedAt) return ['revoked']
  const out: string[] = []
  if (h.staleHeartbeat) out.push('no heartbeat > 1h')
  if (h.staleScan) out.push(h.lastOkScanAt ? 'no successful scan > 48h' : 'never scanned successfully')
  if (h.lastScanStatus === 'error') out.push('last scan failed')
  if (h.rebootRequired) out.push('reboot required')
  if (!h.autoUpdateEnabled) out.push('auto-update off')
  return out
}

export function daysSince(d: Date, now: Date = new Date()): number {
  return Math.max(0, Math.floor((now.getTime() - d.getTime()) / 86_400_000))
}

export function pageCount(p: Pick<Page<unknown>, 'total' | 'pageSize'>): number {
  return Math.max(1, Math.ceil(p.total / p.pageSize))
}

/** Accepting or dismissing a finding needs a reason, so the decision is auditable. */
export function triageNeedsNote(status: TriageStatus): boolean {
  return status !== 'open'
}

const CLIENT_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/

export function isValidClientName(name: string): boolean {
  return CLIENT_NAME.test(name)
}
