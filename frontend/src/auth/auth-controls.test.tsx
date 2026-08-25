import type { AccountInfo } from '@azure/msal-browser'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { AuthControls } from '@/auth/auth-controls'
import { PrincipalSessionProvider } from '@/auth/principal-session'

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

const principal = {
  id: 12,
  display_name: 'Alice Operator',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'stable-subject',
  roles: ['sysadmin'],
  permissions: ['devices:read'],
}

function renderControls(queryClient = new QueryClient()) {
  render(
    <QueryClientProvider client={queryClient}>
      <PrincipalSessionProvider principal={principal}>
        <AuthControls />
      </PrincipalSessionProvider>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('authentication controls', () => {
  it('explains trusted access without identity claims', async () => {
    const user = userEvent.setup()
    renderControls()

    await user.click(
      screen.getByRole('button', { name: 'Account access for Alice Operator' }),
    )

    expect(screen.getByText('System administrator')).toBeVisible()
    expect(screen.getByText('View registered devices.')).toBeVisible()
    expect(document.body).not.toHaveTextContent('stable-subject')
    expect(document.body).not.toHaveTextContent(
      'https://login.example/tenant/v2.0',
    )
  })

  it('renders a safe handled error when logout redirect fails', async () => {
    const user = userEvent.setup()
    const queryClient = new QueryClient()
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const errorSpy = vi
      .spyOn(console, 'error')
      .mockImplementation(() => undefined)
    instance.logoutRedirect.mockRejectedValueOnce(
      new Error('stable-oauth-subject sensitive-account'),
    )

    renderControls(queryClient)

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
