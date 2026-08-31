import { randomUUID } from 'node:crypto'

import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const controlledToken = randomUUID()
const markers = [
  controlledToken,
  'Controlled E2E identity',
  'E2E administrator',
  'ovpncp:e2e:controlled-role',
  'VITE_E2E_ACCESS_TOKEN',
  '/__e2e/auth-return',
]
const vite = fileURLToPath(
  new URL('../node_modules/vite/bin/vite.js', import.meta.url),
)
const outputRoot = mkdtempSync(join(tmpdir(), 'ovpncp-e2e-guard-'))
const environment = {
  ...process.env,
  VITE_AUTH_DISABLED: 'false',
  VITE_E2E_ACCESS_TOKEN: controlledToken,
  VITE_E2E_AUTH_MODE: 'true',
}

function buildAndInspect(mode) {
  const outputDirectory = join(outputRoot, mode)
  const modeArguments = mode === 'e2e' ? ['--mode', 'e2e'] : []
  execFileSync(
    process.execPath,
    [
      vite,
      'build',
      ...modeArguments,
      '--emptyOutDir',
      '--outDir',
      outputDirectory,
    ],
    {
      env: environment,
      stdio: 'inherit',
    },
  )

  const outputFiles = readdirSync(outputDirectory, {
    recursive: true,
  }).filter((entry) => typeof entry === 'string')
  for (const relativePath of outputFiles) {
    const absolutePath = join(outputDirectory, relativePath)
    let content
    try {
      content = readFileSync(absolutePath, 'utf8')
    } catch {
      continue
    }
    for (const marker of markers) {
      if (content.includes(marker)) {
        throw new Error(`Controlled E2E marker survived ${mode} build.`)
      }
    }
  }
}

try {
  buildAndInspect('production')
  buildAndInspect('e2e')
  process.stdout.write(
    'Controlled E2E authentication is absent from production builds.\n',
  )
} finally {
  rmSync(outputRoot, { force: true, recursive: true })
}
