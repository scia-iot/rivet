import type {
  AccountInfo,
  IPublicClientApplication,
} from '@azure/msal-browser'
import { QueryClient } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import {
  clearAuthenticationRedirectGuard,
  redirectForInteraction,
  redirectForLogin,
  signOutAndClearSession,
} from '@/auth/redirect-coordinator'

function createInstance() {
  return {
    acquireTokenRedirect: vi.fn(async () => undefined),
    getActiveAccount: vi.fn(() => null),
    loginRedirect: vi.fn(async () => undefined),
    logoutRedirect: vi.fn(async () => undefined),
    setActiveAccount: vi.fn(),
  } as unknown as IPublicClientApplication
}

const account = {
  homeAccountId: 'home-account',
  environment: 'login.example',
  tenantId: 'tenant',
  username: 'operator@example.com',
  localAccountId: 'local-account',
  name: 'Operator',
} satisfies AccountInfo

beforeEach(() => {
  sessionStorage.clear()
  clearAuthenticationRedirectGuard()
  window.history.replaceState({}, '', '/users?tab=access')
})

describe('authentication redirect coordination', () => {
  it('starts login once and preserves the intended route', async () => {
    const instance = createInstance()

    expect(await redirectForLogin(instance)).toBe(true)
    expect(await redirectForLogin(instance)).toBe(false)

    expect(instance.loginRedirect).toHaveBeenCalledTimes(1)
    expect(instance.loginRedirect).toHaveBeenCalledWith(
      expect.objectContaining({
        redirectStartPage: window.location.href,
      }),
    )
  })

  it('uses only one interaction-required token redirect', async () => {
    const instance = createInstance()

    expect(await redirectForInteraction(instance, account)).toBe(true)
    expect(await redirectForInteraction(instance, account)).toBe(false)

    expect(instance.acquireTokenRedirect).toHaveBeenCalledTimes(1)
    expect(instance.acquireTokenRedirect).toHaveBeenCalledWith(
      expect.objectContaining({ account }),
    )
  })

  it('clears query and active-account state before sign-out', async () => {
    const instance = createInstance()
    const queryClient = new QueryClient()
    queryClient.setQueryData(['me'], { display_name: 'Operator' })

    await signOutAndClearSession(instance, queryClient, account)

    expect(queryClient.getQueryData(['me'])).toBeUndefined()
    expect(instance.setActiveAccount).toHaveBeenCalledWith(null)
    expect(instance.logoutRedirect).toHaveBeenCalledWith(
      expect.objectContaining({ account }),
    )
  })

  it('normalizes sensitive logout failures', async () => {
    const instance = createInstance()
    const queryClient = new QueryClient()
    vi.mocked(instance.logoutRedirect).mockRejectedValueOnce(
      new Error('stable-oauth-subject sensitive-account'),
    )
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)

    await expect(
      signOutAndClearSession(instance, queryClient, account),
    ).rejects.toThrow('Sign-out could not be completed.')

    expect(logSpy).not.toHaveBeenCalled()
    expect(errorSpy).not.toHaveBeenCalled()
  })
})
