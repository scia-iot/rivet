import { useMemo } from 'react'

import { apiBaseUrl, createApiClient } from '@/api/client'
import { useBrowserAuthentication } from '@/auth/browser-authentication'

export function useApiClient() {
  const { accessToken } = useBrowserAuthentication()
  return useMemo(
    () => createApiClient(apiBaseUrl, accessToken),
    [accessToken],
  )
}
