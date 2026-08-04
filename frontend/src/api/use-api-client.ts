import { useMsal } from '@azure/msal-react'
import { useMemo } from 'react'

import { apiBaseUrl, createApiClient } from '@/api/client'
import { apiScopes } from '@/auth/config'

export function useApiClient() {
  const { accounts, instance } = useMsal()

  return useMemo(
    () =>
      createApiClient(apiBaseUrl, async () => {
        const account = instance.getActiveAccount() ?? accounts[0]
        if (account === undefined) {
          throw new Error('An authenticated account is required for API requests.')
        }

        const result = await instance.acquireTokenSilent({
          account,
          scopes: apiScopes,
        })
        return result.accessToken
      }),
    [accounts, instance],
  )
}
