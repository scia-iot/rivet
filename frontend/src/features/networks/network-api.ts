import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type RestrictedNetwork = components['schemas']['RestrictedNetwork']
export type RestrictedNetworkRequest =
  components['schemas']['RestrictedNetworkRequest']

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function useRestrictedNetworks() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.networks.all,
    queryFn: async () => {
      const { data } = await client.GET('/networks')
      return requiredResponse(data, 'restricted network list')
    },
  })
}

export function useRestrictedNetwork(networkId: number, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.networks.detail(networkId),
    queryFn: async () => {
      const { data } = await client.GET('/networks/{network_id}', {
        params: { path: { network_id: networkId } },
      })
      return requiredResponse(data, 'restricted network')
    },
  })
}

export function useCreateRestrictedNetwork() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (request: RestrictedNetworkRequest) => {
      const { data } = await client.POST('/networks', { body: request })
      return requiredResponse(data, 'created restricted network')
    },
    onSuccess: () =>
      queryClient.invalidateQueries({
        exact: true,
        queryKey: queryKeys.networks.all,
      }),
  })
}

export function useCloseRestrictedNetwork() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (networkId: number) => {
      await client.DELETE('/networks/{network_id}', {
        params: { path: { network_id: networkId } },
      })
    },
    onSuccess: async (_data, networkId) => {
      await Promise.all([
        queryClient.invalidateQueries({
          exact: true,
          queryKey: queryKeys.networks.all,
        }),
        queryClient.invalidateQueries({
          exact: true,
          queryKey: queryKeys.networks.detail(networkId),
        }),
      ])
    },
  })
}
