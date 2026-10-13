import { randomUUID } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const playwright = fileURLToPath(
  new URL('../node_modules/@playwright/test/cli.js', import.meta.url),
)
const environment = {
  ...process.env,
  RIVET_E2E_TOKEN: randomUUID(),
}

execFileSync(
  process.execPath,
  [playwright, 'test', ...process.argv.slice(2)],
  {
    env: environment,
    stdio: 'inherit',
  },
)
