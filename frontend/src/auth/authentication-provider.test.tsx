import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

afterEach(() => {
  vi.unstubAllEnvs()
  vi.resetModules()
})

describe('AuthenticationProvider', () => {
  it('blocks the application when Entra configuration is incomplete', async () => {
    vi.stubEnv('VITE_AUTH_DISABLED', 'false')
    vi.stubEnv('VITE_ENTRA_TENANT_ID', '')
    vi.stubEnv('VITE_ENTRA_CLIENT_ID', '')
    vi.stubEnv('VITE_ENTRA_API_SCOPE', '')
    vi.resetModules()

    const { AuthenticationProvider } = await import(
      '@/auth/authentication-provider'
    )

    render(
      <AuthenticationProvider>
        <p>Protected application</p>
      </AuthenticationProvider>,
    )

    expect(screen.getByRole('alert')).toHaveTextContent(
      'Authentication configuration required',
    )
    expect(screen.queryByText('Protected application')).not.toBeInTheDocument()
  })
})
