import { defineConfig, devices } from '@playwright/test'

const port = 4173
const controlledToken = process.env.RIVET_E2E_TOKEN?.trim()
if (!controlledToken) {
  throw new Error('The controlled E2E token is required.')
}

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: 'python e2e/support/controlled_api.py',
      env: {
        ...process.env,
        RIVET_E2E_TOKEN: controlledToken,
      },
      reuseExistingServer: false,
      url: 'http://127.0.0.1:8765/__e2e/ready',
    },
    {
      command:
        `npm run dev -- --mode e2e --host 127.0.0.1 --port ${port}`,
      env: {
        ...process.env,
        RIVET_E2E_API_TARGET: 'http://127.0.0.1:8765',
        VITE_AUTH_DISABLED: 'false',
        VITE_E2E_ACCESS_TOKEN: controlledToken,
        VITE_E2E_AUTH_MODE: 'true',
      },
      reuseExistingServer: !process.env.CI,
      url: `http://127.0.0.1:${port}`,
    },
  ],
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
