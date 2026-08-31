import type { AccountInfo } from '@azure/msal-browser'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiProblemError } from '@/api/problem-details'
import { AuthenticationGate } from '@/auth/authentication-gate'
import {
  clearAuthenticationRedirectGuard,
  redirectForLogin,
} from '@/auth/redirect-coordinator'

const account = {
  homeAccountId: 'home-account',
  environment: 'login.example',
  tenantId: 'tenant',
  username: 'operator@example.com',
  localAccountId: 'local-account',
} satisfies AccountInfo

const state = vi.hoisted(() => ({
  accounts: [] as AccountInfo[],
  authenticated: false,
  inProgress: 'none',
  principal: {
    data: undefined as unknown,
    error: null as unknown,
    isPending: false,
  },
}))

const instance = vi.hoisted(() => ({
  getActiveAccount: vi.fn<() => AccountInfo | null>(() => null),
  loginRedirect: vi.fn(async () => undefined),
  setActiveAccount: vi.fn(),
}))

vi.mock('@/auth/config', () => ({
  apiScopes: ['api://test/access'],
  isAuthenticationDisabled: false,
  isE2EAuthenticationMode: false,
  loginRequest: { scopes: ['api://test/access'] },
}))
vi.mock('@azure/msal-react', () => ({
  useIsAuthenticated: () => state.authenticated,
  useMsal: () => ({
    accounts: state.accounts,
    inProgress: state.inProgress,
    instance,
  }),
}))
vi.mock('@/auth/current-principal', () => ({
  useCurrentPrincipal: () => state.principal,
}))

beforeEach(() => {
  sessionStorage.clear()
  clearAuthenticationRedirectGuard()
  state.accounts = []
  state.authenticated = false
  state.inProgress = 'none'
  state.principal = {
    data: undefined,
    error: null,
    isPending: false,
  }
  instance.getActiveAccount.mockReturnValue(null)
  instance.loginRedirect.mockReset()
  instance.loginRedirect.mockResolvedValue(undefined)
  instance.setActiveAccount.mockClear()
  window.history.replaceState({}, '', '/users?tab=access')
})

describe('configured authentication gate', () => {
  it('stays signed out until the user explicitly starts login', async () => {
    const user = userEvent.setup()

    render(
      <AuthenticationGate>
        <p>Protected application</p>
      </AuthenticationGate>,
    )

    expect(screen.getByRole('heading', { name: 'Signed out' })).toBeVisible()
    expect(instance.loginRedirect).not.toHaveBeenCalled()
    expect(screen.queryByText('Protected application')).not.toBeInTheDocument()

    const signIn = screen.getByRole('button', { name: 'Sign in' })
    await user.click(signIn)
    expect(signIn).toBeDisabled()
    await user.click(signIn)

    expect(instance.loginRedirect).toHaveBeenCalledTimes(1)
    expect(instance.loginRedirect).toHaveBeenCalledWith(
      expect.objectContaining({ redirectStartPage: window.location.href }),
    )
  })

  it('does not redirect again when principal resolution remains unauthorized', async () => {
    state.accounts = [account]
    state.authenticated = true
    state.principal = {
      data: undefined,
      error: new ApiProblemError({
        type: '/errors/unauthorized',
        title: 'Unauthorized',
        status: 401,
        detail: 'Authentication required.',
        instance: '/me',
      }),
      isPending: false,
    }
    await redirectForLogin(instance as never)
    instance.getActiveAccount.mockReturnValue(null)
    const view = render(
      <AuthenticationGate>
        <p>Protected application</p>
      </AuthenticationGate>,
    )

    await waitFor(() => expect(instance.loginRedirect).toHaveBeenCalledTimes(1))
    expect(instance.setActiveAccount).toHaveBeenCalledWith(account)
    view.rerender(
      <AuthenticationGate><p>Protected application</p></AuthenticationGate>,
    )
    expect(instance.loginRedirect).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('heading', { name: 'Signing you in' })).toBeVisible()
  })
})
