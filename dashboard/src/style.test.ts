import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

// Production CSP is default-src 'self': the SPA must not load remote assets.
// (`shadcn-vue add` has re-inserted a Google Fonts import before.)
describe('style.css', () => {
  it('has no remote imports', () => {
    const css = readFileSync(new URL('./style.css', import.meta.url), 'utf8')
    expect(css).not.toMatch(/@import\s+url\(\s*['"]?https?:/)
  })
})
