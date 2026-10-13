import { randomUUID } from 'node:crypto'

import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
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
  'rivet:e2e:controlled-role',
  'VITE_E2E_ACCESS_TOKEN',
  '/__e2e/auth-return',
]
const vite = fileURLToPath(
  new URL('../node_modules/vite/bin/vite.js', import.meta.url),
)
const outputRoot = mkdtempSync(join(tmpdir(), 'rivet-e2e-guard-'))
const sourceRoot = fileURLToPath(new URL('..', import.meta.url))
const buildRoot = join(outputRoot, 'source')
mkdirSync(buildRoot)
for (const path of [
  'src', 'public', 'index.html', 'vite.config.ts', 'package.json',
]) {
  cpSync(join(sourceRoot, path), join(buildRoot, path), { recursive: true })
}
symlinkSync(join(sourceRoot, 'node_modules'), join(buildRoot, 'node_modules'))
const deploymentMarker = randomUUID()
const environment = {
  ...process.env,
  VITE_AUTH_DISABLED: 'false',
  VITE_ENTRA_TENANT_ID: '11111111-1111-1111-1111-111111111111',
  VITE_ENTRA_CLIENT_ID: '22222222-2222-2222-2222-222222222222',
  VITE_ENTRA_API_SCOPE: 'api://test-api/access',
  VITE_API_BASE_URL: '/api',
  VITE_E2E_ACCESS_TOKEN: controlledToken,
  VITE_E2E_AUTH_MODE: 'true',
}

function buildAndInspect(mode) {
  const outputDirectory = join(outputRoot, mode)
  const modeArguments = ['--mode', mode]
  const buildEnvironment = { ...environment }
  const forbiddenMarkers = [...markers]
  if (mode === 'container') {
    buildEnvironment.VITE_ENTRA_TENANT_ID = deploymentMarker
    delete buildEnvironment.VITE_ENTRA_CLIENT_ID
    buildEnvironment.VITE_ENTRA_API_SCOPE = `api://${deploymentMarker}/access`
    buildEnvironment.VITE_API_BASE_URL = `https://${deploymentMarker}.example/api`
    buildEnvironment.VITE_AUTH_DISABLED = 'true'
    // Synthetic files prove that container mode ignores all dotenv input.
    for (const name of [
      '.env', '.env.local', '.env.container', '.env.container.local',
      '.env.production', '.env.production.local',
    ]) {
      writeFileSync(join(buildRoot, name),
        `VITE_ENTRA_CLIENT_ID=${deploymentMarker}\nVITE_AUTH_DISABLED=true\n`)
    }
    forbiddenMarkers.push(deploymentMarker)
  }
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
      env: buildEnvironment,
      cwd: buildRoot,
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
    for (const marker of forbiddenMarkers) {
      if (content.includes(marker)) {
        throw new Error(`Controlled E2E marker survived ${mode} build.`)
      }
    }
  }
}

try {
  buildAndInspect('production')
  buildAndInspect('e2e')
  buildAndInspect('container')
  if (process.argv.includes('--browser')) {
    const { checkContainerBrowser } = await import('./check_container_browser.mjs')
    await checkContainerBrowser(join(outputRoot, 'container'))
  }
  process.stdout.write(
    'Production builds exclude controlled E2E authentication; container assets exclude deployment inputs.\n',
  )
} finally {
  rmSync(outputRoot, { force: true, recursive: true })
}
