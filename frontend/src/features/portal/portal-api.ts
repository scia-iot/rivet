import { useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'

import { triggerArchiveDownload } from '@/api/download'
import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type PortalClient = components['schemas']['CurrentUserClient']
export type PortalDevice = components['schemas']['Device']

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function usePortalClients() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.portal.clients,
    queryFn: async () => {
      const { data } = await client.GET('/me/clients')
      return requiredResponse(data, 'owned VPN client list')
    },
  })
}

export function usePortalDevices() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.portal.devices,
    queryFn: async () => {
      const { data } = await client.GET('/me/devices')
      return requiredResponse(data, 'granted device list')
    },
  })
}

export function usePortalDevice(deviceId: number, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.portal.device(deviceId),
    queryFn: async () => {
      const { data } = await client.GET('/me/devices/{device_id}', {
        params: { path: { device_id: deviceId } },
      })
      return requiredResponse(data, 'granted device')
    },
  })
}

export function usePortalCredentialDownload() {
  const client = useApiClient()
  return useCallback(
    async (clientName: string) => {
      await client.PUT('/me/clients/{client_name}/package-cert', {
        params: { path: { client_name: clientName } },
      })
      const { data } = await client.GET(
        '/me/clients/{client_name}/download-cert',
        {
          cache: 'no-store',
          params: { path: { client_name: clientName } },
          parseAs: 'blob',
        },
      )
      if (!(data instanceof Blob)) {
        throw new Error('The certificate archive response was invalid.')
      }
      triggerArchiveDownload(data, `${clientName}.zip`)
    },
    [client],
  )
}
