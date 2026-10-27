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
