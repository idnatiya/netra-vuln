import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vitest/config'

// Dev: the SPA runs on localhost and proxies /api to a running central
// (make central-dev). The session cookie is Secure, which browsers allow on localhost.
const central = process.env.CENTRAL_DEV_URL ?? 'http://127.0.0.1:18080'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    strictPort: true,
    // Keep the browser's Host so central's same-origin check matches the Origin header.
    proxy: { '/api': { target: central, changeOrigin: false } },
  },
  test: {
    include: ['src/**/*.test.ts'],
  },
})
