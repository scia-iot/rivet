import { configDefaults, defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

const DEFAULT_API_PROXY_TARGET = 'http://127.0.0.1:8000'

export default defineConfig(({ mode }) => ({
  // Container assets must never consume deployment-specific dotenv or VITE_* values.
  ...(mode === 'container' ? {
    envDir: false as const,
    envPrefix: [],
    define: {
      'import.meta.env': JSON.stringify({
        BASE_URL: '/', MODE: 'container', DEV: false, PROD: true,
        VITE_RUNTIME_CONFIG: 'true',
        VITE_API_BASE_URL: '/api', VITE_AUTH_DISABLED: 'false',
      }),
    },
  } : {}),
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    proxy: {
      '/api': {
        target:
          mode === 'e2e'
            ? process.env.RIVET_E2E_API_TARGET ||
              DEFAULT_API_PROXY_TARGET
            : DEFAULT_API_PROXY_TARGET,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  test: {
    environment: 'jsdom',
    exclude: [...configDefaults.exclude, 'scripts/**', 'e2e/**'],
    setupFiles: './src/test/setup.ts',
  },
}))
