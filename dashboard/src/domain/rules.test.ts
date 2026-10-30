import { describe, expect, it } from 'vitest'
import type { Host } from './models'
import { componentAdvice, dailyTotals, daysSince, hostHealth, hostIssues, hostLevel, inHostTab, isRunningKernel, isValidClientName, pageCount, triageNeedsNote, worstFirst } from './rules'

const base: Host = {
  id: 1, client: 'a', hostname: 'vm', osFamily: 'debian', osName: 'Ubuntu', osVersion: '24.04', arch: 'amd64',
  kernelRunning: '6.8', agentVersion: '1', trivyVersion: '0.72.0', rebootRequired: false, autoUpdateEnabled: true,
  lastHeartbeatAt: new Date(), lastScanAt: new Date(), lastScanStatus: 'ok', lastOkScanAt: new Date(),
  createdAt: new Date(), revokedAt: null, openCritical: 0, openHigh: 0, accepted: 0, falsePositive: 0,
  staleScan: false, staleHeartbeat: false, newInLastScan: 0, resolvedInLastScan: 0, firstScan: false,
}

describe('hostHealth', () => {
  it('ranks revoked > stale > attention > healthy', () => {
    expect(hostHealth(base)).toBe('healthy')
    expect(hostHealth({ ...base, openCritical: 1 })).toBe('attention')
    expect(hostHealth({ ...base, autoUpdateEnabled: false })).toBe('attention')
    expect(hostHealth({ ...base, staleHeartbeat: true, openCritical: 3 })).toBe('stale')
    expect(hostHealth({ ...base, revokedAt: new Date(), staleScan: true })).toBe('revoked')
  })
})

describe('hostIssues', () => {
  it('lists every reason, most urgent first', () => {
    const h = { ...base, staleHeartbeat: true, staleScan: true, lastOkScanAt: null, rebootRequired: true, autoUpdateEnabled: false }
    expect(hostIssues(h)).toEqual(['no heartbeat > 1h', 'never scanned successfully', 'reboot required', 'auto-update off'])
    expect(hostIssues(base)).toEqual([])
  })
})

describe('helpers', () => {
  it('daysSince never goes negative', () => {
    const now = new Date('2026-01-10T00:00:00Z')
    expect(daysSince(new Date('2026-01-01T12:00:00Z'), now)).toBe(8)
    expect(daysSince(new Date('2026-02-01T00:00:00Z'), now)).toBe(0)
  })
  it('pageCount is at least 1', () => {
    expect(pageCount({ total: 0, pageSize: 50 })).toBe(1)
    expect(pageCount({ total: 101, pageSize: 50 })).toBe(3)
  })
  it('triage note and client name rules', () => {
    expect(triageNeedsNote('open')).toBe(false)
    expect(triageNeedsNote('accepted')).toBe(true)
    expect(isValidClientName('client_a')).toBe(true)
    expect(isValidClientName('Client A')).toBe(false)
  })
})

describe('isRunningKernel', () => {
  it('matches Ubuntu and RHEL version formats', () => {
    expect(isRunningKernel('6.8.0-147.147', '6.8.0-147-generic')).toBe(true)
    expect(isRunningKernel('6.8.0-124.124', '6.8.0-147-generic')).toBe(false)
    expect(isRunningKernel('5.14.0-427.13.1.el9_4', '5.14.0-427.13.1.el9_4.x86_64')).toBe(true)
    expect(isRunningKernel('5.14.0-362.8.1.el9_3', '5.14.0-427.13.1.el9_4.x86_64')).toBe(false)
    expect(isRunningKernel('6.8.0-124.124', '')).toBe(false)
  })
})

describe('componentAdvice', () => {
  const ubuntu = { osFamily: 'debian', kernelRunning: '6.8.0-147-generic' }
  const kernel = { kind: 'os' as const, packages: ['linux-image-6.8.0-124-generic', 'linux-modules-6.8.0-124-generic'], pkgCount: 2, types: ['ubuntu'] }

  it('tells a fallback kernel from the running one', () => {
    const old = componentAdvice({ ...kernel, key: '6.8.0-124.124' }, ubuntu)
    expect(old.kernel).toBe('standby')
    expect(old.command).toBe("dpkg -l 'linux-*6.8.0-124*' | awk '/^ii/{print $2}' | xargs sudo apt-get purge -y")
    expect(componentAdvice({ ...kernel, key: '6.8.0-147.147' }, ubuntu).kernel).toBe('running')
  })

  it('upgrades listed OS packages, or everything when the list is capped', () => {
    const c = { kind: 'os' as const, key: '3.0.13-0ubuntu3.5', packages: ['libssl3', 'openssl'], pkgCount: 2, types: ['ubuntu'] }
    expect(componentAdvice(c, ubuntu).command).toBe('sudo apt-get update && sudo apt-get install --only-upgrade -y libssl3 openssl')
    expect(componentAdvice(c, { osFamily: 'rhel', kernelRunning: '' }).command).toBe('sudo dnf upgrade -y libssl3 openssl')
    expect(componentAdvice({ ...c, pkgCount: 30 }, { osFamily: 'rhel', kernelRunning: '' }).command).toBe('sudo dnf upgrade -y')
  })

  it('picks a fix per app type and path', () => {
    const app = { kind: 'app' as const, packages: ['laravel/framework'], pkgCount: 1 }
    expect(componentAdvice({ ...app, key: '/var/www/shop', types: ['composer-vendor'] }, ubuntu))
      .toMatchObject({ title: 'shop', command: 'cd /var/www/shop && composer update --with-dependencies laravel/framework' })
    expect(componentAdvice({ ...app, key: '/home/u/.m2', types: ['jar'] }, ubuntu).command).toBeUndefined()
    expect(componentAdvice({ kind: 'binary', key: '/usr/bin/dockerd', packages: ['stdlib'], pkgCount: 1, types: ['gobinary'] }, ubuntu))
      .toMatchObject({ title: 'dockerd', command: 'dpkg -S /usr/bin/dockerd' })
  })
})

describe('hostLevel', () => {
  it('uses the worst open severity, none before the first good scan', () => {
    expect(hostLevel({ ...base, openCritical: 1, openHigh: 5 })).toBe('critical')
    expect(hostLevel({ ...base, openHigh: 2 })).toBe('high')
    expect(hostLevel(base)).toBe('clean')
    expect(hostLevel({ ...base, lastOkScanAt: null })).toBe('none')
  })
})

describe('inHostTab', () => {
  it('splits hosts into the list tabs', () => {
    const revoked = { ...base, revokedAt: new Date(), openCritical: 3 }
    const stale = { ...base, staleHeartbeat: true }
    const open = { ...base, openHigh: 1 }
    expect([base, revoked, stale, open].filter((h) => inHostTab(h, 'attention'))).toEqual([stale, open])
    expect([base, revoked, stale, open].filter((h) => inHostTab(h, 'all'))).toEqual([base, stale, open])
    expect([base, revoked, stale, open].filter((h) => inHostTab(h, 'stale'))).toEqual([stale])
    expect([base, revoked, stale, open].filter((h) => inHostTab(h, 'revoked'))).toEqual([revoked])
  })
})

describe('worstFirst', () => {
  it('puts stale hosts first, then by open critical, high, name', () => {
    const a = { ...base, hostname: 'a', openHigh: 9 }
    const b = { ...base, hostname: 'b', openCritical: 1 }
    const c = { ...base, hostname: 'c', staleScan: true }
    const d = { ...base, hostname: 'd', openHigh: 9 }
    expect([d, a, b, c].sort(worstFirst).map((h) => h.hostname)).toEqual(['c', 'b', 'a', 'd'])
  })
})

describe('dailyTotals', () => {
  it('fills days without a scan with the previous value', () => {
    const today = new Date(2026, 9, 30)
    const pts = [
      { day: new Date(2026, 9, 27), critical: 1, high: 2 },
      { day: new Date(2026, 9, 29), critical: 0, high: 1 },
    ]
    expect(dailyTotals(pts, 5, today)).toEqual([0, 3, 3, 1, 1])
    expect(dailyTotals([], 3, today)).toEqual([0, 0, 0])
  })
})
