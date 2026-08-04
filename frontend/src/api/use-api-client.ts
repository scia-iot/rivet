import {
  type AccountInfo,
  type IPublicClientApplication,
  InteractionRequiredAuthError,
} from '@azure/msal-browser'
import { useMsal } from '@azure/msal-react'
import { useMemo } from 'react'

import { apiBaseUrl, createApiClient } from '@/api/client'
import { apiScopes } from '@/auth/config'
import { redirectForInteraction } from '@/auth/redirect-coordinator'

export async function acquireAccessToken(
  instance: IPublicClientApplication,
  accounts: readonly AccountInfo[],
): Promise<string> {
  const account = instance.getActiveAccount() ?? accounts[0]
  if (account === undefined) {
    throw new Error('An authenticated account is required for API requests.')
  }

  try {
    const result = await instance.acquireTokenSilent({
      account,
      scopes: apiScopes,
    })
    return result.accessToken
  } catch (error) {
    if (error instanceof InteractionRequiredAuthError) {
      await redirectForInteraction(instance, account)
      throw new Error('Authentication interaction is required.')
    }
    throw new Error('An access token could not be acquired.')
  }
}

export function useApiClient() {
  const { accounts, instance } = useMsal()

  return useMemo(
    () =>
      createApiClient(apiBaseUrl, () => acquireAccessToken(instance, accounts)),
    [accounts, instance],
  )
}
