const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })
const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400_000], ['hour', 3_600_000], ['minute', 60_000],
]

/** "5 minutes ago", "yesterday"; "never" for null. */
export function relative(d: Date | null, now: Date = new Date()): string {
  if (!d) return 'never'
  const diff = d.getTime() - now.getTime()
  for (const [unit, ms] of units) {
    if (Math.abs(diff) >= ms || unit === 'minute') return rtf.format(Math.round(diff / ms), unit)
  }
  return ''
}

export const formatDate = (d: Date) => dateFmt.format(d)
export const formatDateTime = (d: Date | null) => (d ? dateTimeFmt.format(d) : '—')
export const formatNumber = (n: number) => n.toLocaleString()

/** "1 host", "3 hosts". */
export function plural(n: number, word: string): string {
  return `${formatNumber(n)} ${word}${n === 1 ? '' : 's'}`
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** Advisory page for a CVE or GitHub advisory id. */
export function advisoryUrl(id: string): string {
  return id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : `https://avd.aquasec.com/nvd/${id.toLowerCase()}`
}

/** "Chrome on macOS" from a User-Agent header; the raw string when nothing matches. */
export function describeUserAgent(ua: string): string {
  if (!ua) return 'Unknown device'
  const pick = (pairs: [string, string][]) => pairs.find(([m]) => ua.includes(m))?.[1]
  const browser = pick([['Edg/', 'Edge'], ['Firefox/', 'Firefox'], ['Chrome/', 'Chrome'], ['Safari/', 'Safari'], ['curl/', 'curl']])
  const os = pick([['iPhone', 'iPhone'], ['iPad', 'iPad'], ['Android', 'Android'], ['Mac OS X', 'macOS'], ['Windows', 'Windows'], ['Linux', 'Linux']])
  if (!browser) return ua.slice(0, 60)
  return os ? `${browser} on ${os}` : browser
}
