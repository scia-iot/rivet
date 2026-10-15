import { InteractionStatus, type AccountInfo } from '@azure/msal-browser'
import { QueryClient } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { type ReactNode, useState } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useBrowserAuthentication } from '@/auth/browser-authentication'
import { EntraBrowserAuthenticationProvider } from '@/auth/entra-adapter'

const bridge = vi.hoisted(() => ({
  signedIn: false,
  accounts: [] as AccountInfo[],
  inProgress: 'none',
  instance: {
    getActiveAccount: vi.fn(),
    setActiveAccount: vi.fn(),
    acquireTokenSilent: vi.fn(),
  },
  login: vi.fn(),
  logout: vi.fn(),
  clearGuard: vi.fn(),
}))

vi.mock('@/auth/config', () => ({
  apiScopes: ['api://rivet/access_as_user'],
  clientId: '22222222-2222-4222-8222-222222222222',
  tenantId: '11111111-1111-4111-8111-111111111111',
  isAuthenticationConfigured: true,
  isAuthenticationDisabled: false,
  isE2EAuthenticationMode: false,
}))

vi.mock('@azure/msal-react', () => ({
  MsalProvider: ({ children }: { children: ReactNode }) => children,
  useIsAuthenticated: () => bridge.signedIn,
  useMsal: () => ({
    accounts: bridge.accounts,
    inProgress: bridge.inProgress,
    instance: bridge.instance,
  }),
}))

vi.mock('@/auth/redirect-coordinator', () => ({
  redirectForLogin: bridge.login,
  signOutAndClearSession: bridge.logout,
  clearAuthenticationRedirectGuard: bridge.clearGuard,
  redirectForInteraction: vi.fn(),
}))

const account: AccountInfo = {
  homeAccountId: 'home-account',
  environment: 'login.microsoftonline.com',
  tenantId: '11111111-1111-4111-8111-111111111111',
  username: 'operator@example.invalid',
  localAccountId: 'local-account',
}

function Probe({ queryClient }: { queryClient: QueryClient }) {
  const authentication = useBrowserAuthentication()
  const [token, setToken] = useState('none')
  return (
    <>
      <output data-testid="state">
        {JSON.stringify({
          ready: authentication.ready,
          signedIn: authentication.signedIn,
          busy: authentication.busy,
        })}
      </output>
      <output data-testid="token">{token}</output>
      <button onClick={() => void authentication.accessToken().then(setToken)}>
        Token
      </button>
      <button onClick={() => void authentication.signIn()}>Sign in</button>
      <button onClick={() => void authentication.signOut(queryClient)}>
        Sign out
      </button>
      <button onClick={() => authentication.clearRedirectGuard()}>Clear guard</button>
    </>
  )
}

function renderBridge() {
  const queryClient = new QueryClient()
  const view = render(
    <EntraBrowserAuthenticationProvider>
      <Probe queryClient={queryClient} />
    </EntraBrowserAuthenticationProvider>,
  )
  return { ...view, queryClient }
}

beforeEach(() => {
  vi.clearAllMocks()
  bridge.signedIn = false
  bridge.accounts = []
  bridge.inProgress = InteractionStatus.None
  bridge.instance.getActiveAccount.mockReturnValue(null)
  bridge.instance.acquireTokenSilent.mockResolvedValue({ accessToken: 'verified-token' })
  bridge.login.mockResolvedValue(true)
  bridge.logout.mockResolvedValue(undefined)
})

describe('Entra browser authentication context', () => {
  it.each([
    [false, false, InteractionStatus.None, false, false],
    [true, false, InteractionStatus.None, false, false],
    [true, true, InteractionStatus.Startup, false, true],
    [true, true, InteractionStatus.None, true, false],
  ])('exposes readiness from account and interaction state %#', (
    signedIn, hasAccount, inProgress, ready, busy,
  ) => {
    bridge.signedIn = signedIn
    bridge.accounts = hasAccount ? [account] : []
    bridge.inProgress = inProgress
    renderBridge()
    expect(JSON.parse(screen.getByTestId('state').textContent ?? '{}')).toEqual({
      ready, signedIn, busy,
    })
    if (signedIn && hasAccount) {
      expect(bridge.instance.setActiveAccount).toHaveBeenCalledWith(account)
    } else {
      expect(bridge.instance.setActiveAccount).not.toHaveBeenCalled()
    }
  })

  it('keeps the active account and delegates tokens, redirects and sign-out', async () => {
    bridge.signedIn = true
    bridge.accounts = [{ ...account, homeAccountId: 'another-account' }]
    bridge.instance.getActiveAccount.mockReturnValue(account)
    const { queryClient } = renderBridge()
    expect(bridge.instance.setActiveAccount).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Token' }))
    await waitFor(() => expect(screen.getByTestId('token')).toHaveTextContent('verified-token'))
    expect(bridge.instance.acquireTokenSilent).toHaveBeenCalledWith({
      account, scopes: ['api://rivet/access_as_user'],
    })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clear guard' }))
    expect(bridge.login).toHaveBeenCalledWith(bridge.instance)
    expect(bridge.logout).toHaveBeenCalledWith(bridge.instance, queryClient, account)
    expect(bridge.clearGuard).toHaveBeenCalledOnce()
  })
})
