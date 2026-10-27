import { describe, expect, it, vi } from 'vitest'
import { ApiError } from './errors'
import type { Repositories } from './ports'
import { createUseCases } from './usecases'

function fakeRepos() {
  const r = {
    auth: { login: vi.fn(), logout: vi.fn(), me: vi.fn() },
    stats: { overview: vi.fn(), trend: vi.fn(), oldestCVEs: vi.fn(), distribution: vi.fn() },
    findings: { list: vi.fn(), triage: vi.fn() },
    hosts: { list: vi.fn(), revoke: vi.fn() },
    clients: { list: vi.fn(), create: vi.fn(async () => 'tok'), setScanConfig: vi.fn(async (_n, c) => c), clearScanConfig: vi.fn() },
  }
  return r as typeof r & Repositories
}

describe('triageFinding', () => {
  it('requires a note to accept or dismiss', async () => {
    const r = fakeRepos()
    const uc = createUseCases(r)
    await expect(uc.triageFinding(1, 'accepted', '  ')).rejects.toBeInstanceOf(ApiError)
    await uc.triageFinding(1, 'false_positive', ' kernel not booted ')
    await uc.triageFinding(2, 'open', '')
    expect(r.findings.triage.mock.calls).toEqual([[1, 'false_positive', 'kernel not booted'], [2, 'open', '']])
  })
})

describe('createClient', () => {
  it('validates the name before calling the server', async () => {
    const r = fakeRepos()
    const uc = createUseCases(r)
    await expect(uc.createClient('Bad Name')).rejects.toBeInstanceOf(ApiError)
    expect(r.clients.create).not.toHaveBeenCalled()
    expect(await uc.createClient(' acme ')).toEqual({ name: 'acme', enrollToken: 'tok' })
  })
})

describe('saveScanConfig', () => {
  it('clears on empty text, rejects non-objects, forwards objects', async () => {
    const r = fakeRepos()
    const uc = createUseCases(r)
    expect(await uc.saveScanConfig('a', '   ')).toBeNull()
    expect(r.clients.clearScanConfig).toHaveBeenCalledWith('a')
    await expect(uc.saveScanConfig('a', '{oops')).rejects.toThrow('not valid JSON')
    await expect(uc.saveScanConfig('a', '["x"]')).rejects.toThrow('JSON object')
    expect(await uc.saveScanConfig('a', '{"severity":["CRITICAL"]}')).toEqual({ severity: ['CRITICAL'] })
  })
})

describe('listFindings', () => {
  it('drops a blank search query', async () => {
    const r = fakeRepos()
    await createUseCases(r).listFindings({ page: 1, pageSize: 50, query: '   ' })
    expect(r.findings.list).toHaveBeenCalledWith({ page: 1, pageSize: 50, query: undefined })
  })
})
