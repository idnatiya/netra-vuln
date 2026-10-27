import { describe, expect, it } from 'vitest'
import type { Host } from './models'
import { componentLabel, daysSince, hostHealth, hostIssues, isValidClientName, pageCount, triageNeedsNote } from './rules'

const base: Host = {
  id: 1, client: 'a', hostname: 'vm', osFamily: 'debian', osName: 'Ubuntu', osVersion: '24.04', arch: 'amd64',
  kernelRunning: '6.8', agentVersion: '1', trivyVersion: '0.72.0', rebootRequired: false, autoUpdateEnabled: true,
  lastHeartbeatAt: new Date(), lastScanAt: new Date(), lastScanStatus: 'ok', lastOkScanAt: new Date(),
  createdAt: new Date(), revokedAt: null, openCritical: 0, openHigh: 0, accepted: 0, falsePositive: 0,
  staleScan: false, staleHeartbeat: false,
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

describe('componentLabel', () => {
  it('names kernel groups, other OS groups by package, apps and binaries by path', () => {
    const kernel = { kind: 'os' as const, key: '6.8.0-124.124', packages: ['linux-libc-dev', 'linux-tools-common'], pkgCount: 2 }
    expect(componentLabel(kernel)).toEqual({ title: 'Linux kernel', detail: kernel.key, hint: 'reboot after upgrade' })
    expect(componentLabel({ kind: 'os', key: 'k', packages: ['libssl3', 'openssl', 'x'], pkgCount: 5 }).title).toBe('libssl3, openssl +3')
    expect(componentLabel({ kind: 'app', key: '/var/www/shop', packages: [], pkgCount: 0 })).toEqual({ title: 'shop', detail: '/var/www/shop' })
    expect(componentLabel({ kind: 'binary', key: '/usr/bin/dockerd', packages: [], pkgCount: 0 }).title).toBe('dockerd')
  })
})
