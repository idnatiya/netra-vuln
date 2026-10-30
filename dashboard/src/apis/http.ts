import { ApiError, UnauthorizedError } from '@/apis/errors'

// Thin fetch wrapper for /api/admin/v1. The session lives in an HttpOnly cookie,
// so nothing here touches credentials directly. Responses are wrapped as
// { data, paging?, errors? } (central's model.WebResponse).

export interface PagingDTO { page: number, size: number, total_item: number, total_page: number }
interface Envelope<T> { data: T, paging?: PagingDTO, errors?: string }

export class HttpClient {
  constructor(
    private readonly base: string,
    private readonly onUnauthorized: () => void,
  ) {}

  /** Returns the response's `data`. */
  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    return (await this.envelope<T>(method, path, body)).data
  }

  /** Returns the whole envelope (data and paging), or `data: undefined` on 204. */
  async envelope<T>(method: string, path: string, body?: unknown): Promise<Envelope<T>> {
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
      let message = text
      try {
        message = (JSON.parse(text) as Envelope<unknown>).errors || text
      } catch { /* plain-text error */ }
      throw new ApiError(message || res.statusText, res.status)
    }
    if (res.status === 204) return { data: undefined as T }
    return (await res.json()) as Envelope<T>
  }

  get<T>(path: string, query?: Record<string, string | number | boolean | undefined>) {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== '') qs.set(k, String(v))
    }
    const s = qs.toString()
    return this.request<T>('GET', s ? `${path}?${s}` : path)
  }

  /** GET a paged list: `data` plus `paging`. */
  page<T>(path: string, query: Record<string, string | number | boolean | undefined>) {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== '') qs.set(k, String(v))
    }
    return this.envelope<T[]>('GET', `${path}?${qs}`)
  }
}
