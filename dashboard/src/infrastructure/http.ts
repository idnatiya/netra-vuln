import { ApiError, UnauthorizedError } from '@/application/errors'

// Thin fetch wrapper for /api/admin/v1. The session lives in an HttpOnly cookie,
// so nothing here touches credentials directly.

export class HttpClient {
  constructor(
    private readonly base: string,
    private readonly onUnauthorized: () => void,
  ) {}

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.base + path, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    if (res.status === 401) {
      this.onUnauthorized()
      throw new UnauthorizedError()
    }
    if (!res.ok) {
      const text = (await res.text()).trim()
      throw new ApiError(text || res.statusText, res.status)
    }
    if (res.status === 204) return undefined as T
    return (await res.json()) as T
  }

  get<T>(path: string, query?: Record<string, string | number | boolean | undefined>) {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== '') qs.set(k, String(v))
    }
    const s = qs.toString()
    return this.request<T>('GET', s ? `${path}?${s}` : path)
  }
}
