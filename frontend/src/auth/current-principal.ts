import { useQuery } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type CurrentPrincipal = components['schemas']['CurrentPrincipal']

export function useCurrentPrincipal(enabled = true) {
  const client = useApiClient()

  return useQuery({
    enabled,
    queryKey: queryKeys.currentPrincipal.detail,
    queryFn: async () => {
      const { data } = await client.GET('/me')
      if (data === undefined) {
        throw new Error('The current principal response was empty.')
      }
      return data
    },
  })
}
