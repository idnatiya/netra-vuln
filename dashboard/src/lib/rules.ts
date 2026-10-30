import type { Component, Host, Page, TrendPoint, TriageStatus } from '@/types/models'

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

/** The colour band of a host row: worst open severity, or none before the first successful scan. */
export type HostLevel = 'critical' | 'high' | 'clean' | 'none'

export function hostLevel(h: Host): HostLevel {
  if (h.openCritical > 0) return 'critical'
  if (h.openHigh > 0) return 'high'
  return h.lastOkScanAt ? 'clean' : 'none'
}

export type HostTab = 'attention' | 'all' | 'stale' | 'revoked'

/** Which hosts each tab of the hosts list shows. "attention" = active hosts with open findings or issues. */
export function inHostTab(h: Host, tab: HostTab): boolean {
  if (tab === 'revoked') return h.revokedAt !== null
  if (h.revokedAt) return false
  if (tab === 'stale') return h.staleScan || h.staleHeartbeat
  if (tab === 'attention') return h.openCritical > 0 || h.openHigh > 0 || hostIssues(h).length > 0
  return true
}

/** Worst first: stale, then most open critical, then most open high, then by name. */
export function worstFirst(a: Host, b: Host): number {
  const stale = (h: Host) => Number(h.staleScan || h.staleHeartbeat)
  return stale(b) - stale(a) || b.openCritical - a.openCritical || b.openHigh - a.openHigh
    || a.hostname.localeCompare(b.hostname)
}

/**
 * One value per day for the last `days` days ending today, for sparklines. Days
 * without a successful scan carry the previous day's value (findings stay open
 * until a scan resolves them); days before the first point are 0.
 */
export function dailyTotals(points: TrendPoint[], days: number, today: Date = new Date()): number[] {
  const key = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
  const byDay = new Map(points.map((p) => [key(p.day), p.critical + p.high]))
  const out: number[] = []
  let last = 0
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - i)
    last = byDay.get(key(d)) ?? last
    out.push(last)
  }
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

/** What a component is and how to fix it, for one host. */
export interface ComponentAdvice {
  title: string
  detail: string
  /** Plain-language next step. */
  note: string
  /** Shell command to run on the host, when one applies. */
  command?: string
  /** For kernels: whether this version is the one running now. */
  kernel?: 'running' | 'standby'
}

const basename = (p: string) => p.split('/').filter(Boolean).pop() ?? p
const isKernel = (pkgs: string[]) => pkgs.length > 0 && pkgs.every((p) => p.startsWith('linux-') || p.startsWith('kernel'))
const CACHE_DIRS = ['.m2', '.cache', '.npm', '.gradle', '.cargo']

/**
 * Whether an installed kernel package version is the running kernel.
 * Ubuntu: running "6.8.0-147-generic", installed "6.8.0-147.147".
 * RHEL: running "5.14.0-427.13.1.el9_4.x86_64", installed "5.14.0-427.13.1.el9_4".
 */
export function isRunningKernel(installed: string, running: string): boolean {
  if (!running || !installed) return false
  const base = running.replace(/-[a-z][a-z0-9]*$/i, '') // drop the flavour, e.g. "-generic"
  return running.startsWith(installed) || installed === base || installed.startsWith(`${base}.`)
}

type AdviceHost = Pick<Host, 'osFamily' | 'kernelRunning'>
type AdviceComponent = Pick<Component, 'kind' | 'key' | 'packages' | 'pkgCount' | 'types'>

export function componentAdvice(c: AdviceComponent, h: AdviceHost): ComponentAdvice {
  const deb = h.osFamily === 'debian'
  const pkgs = c.packages.join(' ')
  const complete = c.packages.length >= c.pkgCount // the package list is capped server-side

  if (c.kind === 'os' && isKernel(c.packages)) {
    if (isRunningKernel(c.key, h.kernelRunning)) {
      return {
        title: 'Linux kernel', detail: c.key, kernel: 'running',
        note: 'This is the running kernel. Upgrade, then reboot into the new one.',
        command: deb ? 'sudo apt-get update && sudo apt-get full-upgrade -y && sudo reboot' : "sudo dnf upgrade -y 'kernel*' && sudo reboot",
      }
    }
    return {
      title: 'Linux kernel', detail: c.key, kernel: 'standby',
      note: `Not running (the host booted ${h.kernelRunning || 'another kernel'}). Kept as a fallback; remove it once the running kernel is fine.`,
      command: deb
        ? `dpkg -l 'linux-*${c.key.replace(/\.[^.]*$/, '')}*' | awk '/^ii/{print $2}' | xargs sudo apt-get purge -y`
        : `sudo dnf remove 'kernel*-${c.key}*'`,
    }
  }
  if (c.kind === 'os') {
    const more = c.pkgCount - Math.min(c.packages.length, 2)
    return {
      title: c.packages.slice(0, 2).join(', ') + (more > 0 ? ` +${more}` : ''), detail: c.key,
      note: 'Upgrade these OS packages.',
      command: deb
        ? `sudo apt-get update && sudo apt-get install --only-upgrade -y ${complete ? pkgs : '$(apt list --upgradable 2>/dev/null | cut -d/ -f1 | tail -n +2)'}`
        : `sudo dnf upgrade -y ${complete ? pkgs : ''}`.trimEnd(),
    }
  }
  if (c.kind === 'binary') {
    return {
      title: basename(c.key), detail: c.key,
      note: 'A compiled binary with outdated libraries. Upgrade the package or app that ships it; this finds the package:',
      command: deb ? `dpkg -S ${c.key}` : `rpm -qf ${c.key}`,
    }
  }
  const title = basename(c.key)
  if (CACHE_DIRS.includes(title)) {
    return { title, detail: c.key, note: 'A package cache, not a running app. Clear it, or accept the risk for this component.' }
  }
  const has = (...t: string[]) => c.types.some((x) => t.includes(x))
  if (has('composer', 'composer-vendor')) {
    return { title, detail: c.key, note: 'PHP app (Composer). Update the dependencies, test, and deploy.', command: `cd ${c.key} && composer update --with-dependencies ${pkgs}` }
  }
  if (has('node-pkg', 'npm', 'yarn', 'pnpm')) {
    return { title, detail: c.key, note: 'Node.js app. Update the dependencies, rebuild, and deploy.', command: `cd ${c.key} && npm update ${pkgs}` }
  }
  if (has('python-pkg', 'pip', 'pipenv', 'poetry', 'uv')) {
    return { title, detail: c.key, note: "Python packages. Upgrade them in the app's environment.", command: `pip install -U ${pkgs}` }
  }
  if (has('jar', 'pom', 'gradle', 'sbt')) {
    return { title, detail: c.key, note: 'Java app. Bump the dependencies in its build, rebuild, and deploy.' }
  }
  return { title, detail: c.key, note: 'Update the dependencies of this app.' }
}
