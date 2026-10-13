import {
  type AccountInfo,
  type IPublicClientApplication,
  InteractionRequiredAuthError,
} from '@azure/msal-browser'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { acquireAccessToken } from '@/api/use-api-client'
import { clearAuthenticationRedirectGuard } from '@/auth/redirect-coordinator'

const account = {
  homeAccountId: 'home-account',
  environment: 'login.example',
  tenantId: 'tenant',
  username: 'operator@example.com',
  localAccountId: 'local-account',
} satisfies AccountInfo

beforeEach(() => {
  sessionStorage.clear()
  clearAuthenticationRedirectGuard()
})

describe('MSAL access token acquisition', () => {
  it('uses one controlled redirect when silent acquisition needs interaction', async () => {
    const instance = {
      acquireTokenSilent: vi.fn(async () => {
        throw new InteractionRequiredAuthError(
          'interaction_required',
          'correlation-id',
          'secret-token stable-oauth-subject',
        )
      }),
      acquireTokenRedirect: vi.fn(async () => undefined),
      getActiveAccount: vi.fn(() => account),
    } as unknown as IPublicClientApplication
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)

    await expect(acquireAccessToken(instance, [account])).rejects.toThrow(
      'Authentication interaction is required.',
    )
    await expect(acquireAccessToken(instance, [account])).rejects.toThrow(
      'Authentication interaction is required.',
    )

    expect(instance.acquireTokenRedirect).toHaveBeenCalledTimes(1)
    expect(logSpy).not.toHaveBeenCalled()
    expect(errorSpy).not.toHaveBeenCalled()
    expect(JSON.stringify([...logSpy.mock.calls, ...errorSpy.mock.calls])).not
      .toContain('stable-oauth-subject')
  })
})
