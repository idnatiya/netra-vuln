import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, UnauthorizedError } from '@/application/errors'
import { HttpClient } from './http'
import { createHttpRepositories } from './repositories'

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn(async () => new Response(status === 204 ? null : typeof body === 'string' ? body : JSON.stringify(body), { status }))
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => vi.unstubAllGlobals())

describe('HttpClient', () => {
  it('maps 401 to UnauthorizedError and notifies', async () => {
    mockFetch(401, 'unauthorized')
    const onUnauth = vi.fn()
    await expect(new HttpClient('/api', onUnauth).get('/me')).rejects.toBeInstanceOf(UnauthorizedError)
    expect(onUnauth).toHaveBeenCalledOnce()
  })
  it('surfaces the server message on 4xx', async () => {
    mockFetch(400, { errors: 'invalid request: sort: oneof' })
    await expect(new HttpClient('/api', () => {}).get('/findings')).rejects.toEqual(new ApiError('invalid request: sort: oneof', 400))
    mockFetch(413, 'Request Entity Too Large')
    await expect(new HttpClient('/api', () => {}).get('/findings')).rejects.toEqual(new ApiError('Request Entity Too Large', 413))
  })
  it('unwraps data', async () => {
    mockFetch(200, { data: { username: 'ops', expires_at: '2026-10-25T16:07:28Z' } })
    expect(await new HttpClient('/api', () => {}).get('/me')).toEqual({ username: 'ops', expires_at: '2026-10-25T16:07:28Z' })
  })
  it('skips empty query params', async () => {
    const f = mockFetch(200, { data: [] })
    await new HttpClient('/api', () => {}).get('/hosts', { client: '', page: 2, q: undefined })
    expect(f).toHaveBeenCalledWith('/api/hosts?page=2', expect.anything())
  })
})

describe('repositories', () => {
  it('maps snake_case findings to domain objects', async () => {
    const f = mockFetch(200, {
      data: [{ id: 7, host_id: 1, client: 'dev', hostname: 'vm', target: 't', type: 'ubuntu', cve: 'CVE-1', pkg: 'openssl',
        installed_version: '1', fixed_version: '2', severity: 'CRITICAL', title: 'x', status: 'open', note: '',
        first_seen: '2026-10-25T16:07:28Z', last_seen: '2026-10-25T16:17:55Z', resolved_at: null }],
      paging: { page: 1, size: 50, total_item: 1, total_page: 1 },
    })
    const repos = createHttpRepositories(new HttpClient('/api', () => {}))
    const page = await repos.findings.list({ page: 1, pageSize: 50, severity: 'CRITICAL', includeResolved: false })
    expect(f).toHaveBeenCalledWith('/api/findings?severity=CRITICAL&page=1&size=50', expect.anything())
    expect(page.items[0]?.installedVersion).toBe('1')
    expect(page.items[0]?.firstSeen).toEqual(new Date('2026-10-25T16:07:28Z'))
    expect(page.pageSize).toBe(50)
  })
})
