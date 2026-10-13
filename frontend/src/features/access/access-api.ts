import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type AuthorizedDevice = components['schemas']['Device']
export type AccessGrant = components['schemas']['AccessGrant']

export interface DeviceAccessRequest {
  userId: number
  deviceId: number
}

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function useUserDevices(userId: number, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.users.devices(userId),
    queryFn: async () => {
      const { data } = await client.GET('/users/{user_id}/devices', {
        params: { path: { user_id: userId } },
      })
      return requiredResponse(data, 'authorized device list')
    },
  })
}

async function invalidateUserDevices(
  queryClient: ReturnType<typeof useQueryClient>,
  userId: number,
) {
  await queryClient.invalidateQueries({
    exact: true,
    queryKey: queryKeys.users.devices(userId),
  })
}

export function useGrantDeviceAccess() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, deviceId }: DeviceAccessRequest) => {
      const { data } = await client.PUT(
        '/users/{user_id}/devices/{device_id}',
        { params: { path: { user_id: userId, device_id: deviceId } } },
      )
      return requiredResponse(data, 'access grant')
    },
    onSuccess: (_data, request) =>
      invalidateUserDevices(queryClient, request.userId),
  })
}

export function useRevokeDeviceAccess() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, deviceId }: DeviceAccessRequest) => {
      await client.DELETE('/users/{user_id}/devices/{device_id}', {
        params: { path: { user_id: userId, device_id: deviceId } },
      })
    },
    onSuccess: (_data, request) =>
      invalidateUserDevices(queryClient, request.userId),
  })
}
