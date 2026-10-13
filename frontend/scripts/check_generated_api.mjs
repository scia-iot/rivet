import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const generatedFiles = [
  'openapi.json',
  'src/api/generated/schema.d.ts',
]
const before = new Map(
  generatedFiles.map((file) => [file, readFileSync(file, 'utf8')]),
)

const generation = spawnSync('npm', ['run', 'api:generate'], {
  shell: process.platform === 'win32',
  stdio: 'inherit',
})

if (generation.status !== 0) {
  process.exit(generation.status ?? 1)
}

const changed = generatedFiles.filter(
  (file) => readFileSync(file, 'utf8') !== before.get(file),
)

if (changed.length > 0) {
  console.error(
    `Generated API files are stale: ${changed.join(', ')}. Run npm run api:generate.`,
  )
  process.exit(1)
}
