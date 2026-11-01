import { describe, expect, it } from 'vitest'
import type { Host } from '@/types/models'
import { agentUpgradeCommand, componentAdvice, dailyTotals, eolLabel, isAgentOutdated, daysSince, hostHealth, hostIssues, hostLevel, inHostTab, isRunningKernel, isValidClientName, mcpClientConfigs, pageCount, worstFirst } from './rules'

const base: Host = {
  id: 1, client: 'a', hostname: 'vm', osFamily: 'debian', osName: 'Ubuntu', osVersion: '24.04', arch: 'amd64',
  kernelRunning: '6.8', agentVersion: '1', trivyVersion: '0.72.0', rebootRequired: false, autoUpdateEnabled: true,
  lastHeartbeatAt: new Date(), lastScanAt: new Date(), lastScanStatus: 'ok', lastOkScanAt: new Date(),
  createdAt: new Date(), revokedAt: null, openCritical: 0, openHigh: 0, accepted: 0, falsePositive: 0,
  staleScan: false, staleHeartbeat: false, newInLastScan: 0, resolvedInLastScan: 0, firstScan: false,
  eol: [], eolSoon: [],
}

describe('hostHealth', () => {
  it('ranks revoked > stale > attention > healthy', () => {
    expect(hostHealth(base)).toBe('healthy')
    expect(hostHealth({ ...base, openCritical: 1 })).toBe('attention')
    expect(hostHealth({ ...base, autoUpdateEnabled: false })).toBe('attention')
    expect(hostHealth({ ...base, eol: ['php 7.4'] })).toBe('attention')
    expect(hostHealth({ ...base, eolSoon: ['nodejs 20'] })).toBe('healthy')
    expect(hostHealth({ ...base, staleHeartbeat: true, openCritical: 3 })).toBe('stale')
    expect(hostHealth({ ...base, revokedAt: new Date(), staleScan: true })).toBe('revoked')
  })
})

describe('hostIssues', () => {
  it('lists every reason, most urgent first', () => {
    const h = { ...base, staleHeartbeat: true, staleScan: true, lastOkScanAt: null, rebootRequired: true, autoUpdateEnabled: false }
    expect(hostIssues(h)).toEqual(['no heartbeat > 1h', 'never scanned successfully', 'reboot required', 'auto-update off'])
    expect(hostIssues(base)).toEqual([])
    expect(hostIssues({ ...base, eol: ['php 7.4'], eolSoon: ['nodejs 20'] })).toEqual(['php 7.4 end of life', 'nodejs 20 EOL soon'])
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
  it('client name rules', () => {
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
      .toMatchObject({ title: 'dockerd', command: expect.stringMatching(/^dpkg -S \/usr\/bin\/dockerd 2>\/dev\/null \|\| echo 'No package owns/) })
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

describe('mcpClientConfigs', () => {
  const configs = mcpClientConfigs('https://vuln.example.com/mcp', 'tok123')
  it('puts the URL and Bearer token into every snippet', () => {
    for (const c of configs) {
      expect(c.snippet, c.id).toContain('https://vuln.example.com/mcp')
      expect(c.snippet, c.id).toContain('Bearer tok123')
    }
  })
  it('emits valid JSON for the JSON-configured clients', () => {
    for (const id of ['opencode', 'antigravity', 'cursor', 'claude-desktop']) {
      expect(() => JSON.parse(configs.find((c) => c.id === id)!.snippet), id).not.toThrow()
    }
  })
  it('uses the Claude Code CLI form', () => {
    expect(configs[0]!.snippet).toBe('claude mcp add --transport http netra-vuln https://vuln.example.com/mcp --header "Authorization: Bearer tok123"')
  })
})

describe('eolLabel', () => {
  const now = new Date('2026-11-01T00:00:00Z')
  it('describes each status', () => {
    expect(eolLabel({ status: 'eol', eol: '2022-11-28', product: 'php', cycle: '7.4' }, now)).toBe('EOL 2022-11-28')
    expect(eolLabel({ status: 'eol', eol: 'true', product: 'vue', cycle: '2' }, now)).toBe('EOL')
    expect(eolLabel({ status: 'soon', eol: '2026-12-01', product: 'nodejs', cycle: '20' }, now)).toBe('EOL in 30 days')
    expect(eolLabel({ status: 'supported', eol: '2027-12-31', product: 'php', cycle: '8.3' }, now)).toBe('until 2027-12-31')
    expect(eolLabel({ status: 'unknown', eol: '', product: '', cycle: '' }, now)).toBe('not tracked')
    expect(eolLabel({ status: 'unknown', eol: '', product: 'php', cycle: '' }, now)).toBe('unknown cycle')
  })
})

describe('agent upgrade', () => {
  it('compares vX.Y.Z numerically and ignores non-releases', () => {
    expect(isAgentOutdated('v0.2.1', 'v0.3.0')).toBe(true)
    expect(isAgentOutdated('v0.9.0', 'v0.10.0')).toBe(true)
    expect(isAgentOutdated('v0.3.0', 'v0.3.0')).toBe(false)
    expect(isAgentOutdated('v0.4.0', 'v0.3.0')).toBe(false)
    expect(isAgentOutdated('dev', 'v0.3.0')).toBe(false)
    expect(isAgentOutdated('', 'v0.3.0')).toBe(false)
    expect(isAgentOutdated('v0.2.1', '')).toBe(false)
  })
  it('re-runs the installer for the client, then scans', () => {
    expect(agentUpgradeCommand('https://vuln.example.com', 'acme'))
      .toBe("curl -fsSL 'https://vuln.example.com/install.sh' | sudo sh -s -- 'acme'\nsudo systemctl start vuln-agent-scan.service")
  })
})
