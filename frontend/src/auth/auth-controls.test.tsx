import type { AccountInfo } from '@azure/msal-browser'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AuthControls } from '@/auth/auth-controls'

const account = {
  homeAccountId: 'home-account',
  environment: 'login.example',
  tenantId: 'tenant',
  username: 'operator@example.com',
  localAccountId: 'local-account',
} satisfies AccountInfo

const instance = vi.hoisted(() => ({
  getActiveAccount: vi.fn(() => account),
  logoutRedirect: vi.fn(async () => undefined),
  setActiveAccount: vi.fn(),
}))

vi.mock('@/auth/config', () => ({
  isAuthenticationConfigured: true,
  isAuthenticationDisabled: false,
}))
vi.mock('@azure/msal-react', () => ({
  useIsAuthenticated: () => true,
  useMsal: () => ({ instance }),
}))

afterEach(() => {
  vi.restoreAllMocks()
})

describe('authentication controls', () => {
  it('renders a safe handled error when logout redirect fails', async () => {
    const user = userEvent.setup()
    const queryClient = new QueryClient()
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    instance.logoutRedirect.mockRejectedValueOnce(
      new Error('stable-oauth-subject sensitive-account'),
    )

    render(
      <QueryClientProvider client={queryClient}>
        <AuthControls />
      </QueryClientProvider>,
    )

    await user.click(screen.getByRole('button', { name: 'Sign out' }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Sign-out could not be completed.',
      ),
    )
    expect(document.body).not.toHaveTextContent('stable-oauth-subject')
    expect(logSpy).not.toHaveBeenCalled()
    expect(errorSpy).not.toHaveBeenCalled()
  })
})
