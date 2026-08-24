import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type ServerConfiguration =
  components['schemas']['ServerWithVirtualAddresses']
export type ServiceHealth = components['schemas']['ServiceHealth']
export type VirtualAddress = components['schemas']['VirtualAddress']

export const SERVER_HEALTH_POLL_INTERVAL_MS = 15_000

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

function useDocumentVisible(): boolean {
  const [visible, setVisible] = useState(
    () => document.visibilityState === 'visible',
  )

  useEffect(() => {
    function updateVisibility() {
      setVisible(document.visibilityState === 'visible')
    }
    document.addEventListener('visibilitychange', updateVisibility)
    return () => {
      document.removeEventListener('visibilitychange', updateVisibility)
    }
  }, [])

  return visible
}

export function useServer(enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.server.all,
    queryFn: async () => {
      const { data } = await client.GET('/server')
      return requiredResponse(data, 'server configuration')
    },
  })
}

export function useServerHealth() {
  const client = useApiClient()
  const visible = useDocumentVisible()
  return useQuery({
    enabled: visible,
    queryKey: queryKeys.server.health,
    queryFn: async () => {
      const { data } = await client.GET('/server/health')
      return requiredResponse(data, 'server health')
    },
    refetchInterval: visible ? SERVER_HEALTH_POLL_INTERVAL_MS : false,
    refetchIntervalInBackground: false,
  })
}

export function useAssignableVirtualAddresses() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.clients.addresses,
    queryFn: async () => {
      const { data } = await client.GET(
        '/server/assignable-virtual-addresses',
      )
      return requiredResponse(data, 'assignable virtual address list')
    },
  })
}

export function useServerRoutes() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.server.routes,
    queryFn: async () => {
      const { data } = await client.GET('/server/routes')
      return requiredResponse(data, 'server route list')
    },
  })
}

export function useInitializeServer() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const { data } = await client.POST('/server')
      return requiredResponse(data, 'initialized server')
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({
          exact: true,
          queryKey: queryKeys.server.all,
        }),
        queryClient.invalidateQueries({
          exact: true,
          queryKey: queryKeys.clients.addresses,
        }),
      ])
    },
  })
}

async function invalidateRoutes(
  queryClient: ReturnType<typeof useQueryClient>,
) {
  await queryClient.invalidateQueries({
    exact: true,
    queryKey: queryKeys.server.routes,
  })
}

export function useAddServerRoute() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (network: string) => {
      await client.POST('/server/routes', { body: { network } })
    },
    onSuccess: () => invalidateRoutes(queryClient),
  })
}

export function useDeleteServerRoute() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (network: string) => {
      await client.DELETE('/server/routes', {
        params: { query: { network } },
      })
    },
    onSuccess: () => invalidateRoutes(queryClient),
  })
}
