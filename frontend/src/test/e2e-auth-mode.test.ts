import { describe, expect, it } from 'vitest'

import { allowsE2EAuthenticationMode } from '@/test/e2e-auth-mode'

describe('controlled E2E authentication mode', () => {
  it('requires an explicit e2e development server', () => {
    expect(
      allowsE2EAuthenticationMode({
        accessToken: 'per-run-value',
        development: true,
        mode: 'e2e',
        requested: 'true',
      }),
    ).toBe(true)
  })

  it('is unavailable in an ordinary production build', () => {
    expect(
      allowsE2EAuthenticationMode({
        accessToken: 'per-run-value',
        development: false,
        mode: 'production',
        requested: 'true',
      }),
    ).toBe(false)
  })

  it('is unavailable to vite build --mode e2e', () => {
    expect(
      allowsE2EAuthenticationMode({
        accessToken: 'per-run-value',
        development: false,
        mode: 'e2e',
        requested: 'true',
      }),
    ).toBe(false)
  })

  it('does not activate without the explicit flag', () => {
    expect(
      allowsE2EAuthenticationMode({
        accessToken: 'per-run-value',
        development: true,
        mode: 'e2e',
        requested: undefined,
      }),
    ).toBe(false)
  })

  it('does not activate without a per-run credential', () => {
    expect(
      allowsE2EAuthenticationMode({
        accessToken: ' ',
        development: true,
        mode: 'e2e',
        requested: 'true',
      }),
    ).toBe(false)
  })
})
