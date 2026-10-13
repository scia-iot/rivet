import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type Device = components['schemas']['Device']
export type DeviceCreate = components['schemas']['DeviceBase']
export type DeviceUpdate = components['schemas']['DeviceUpdate']
export type VpnClient = components['schemas']['Client']

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function useDevices(enabled = true) {
  const client = useApiClient()

  return useQuery({
    enabled,
    queryKey: queryKeys.devices.all,
    queryFn: async () => {
      const { data } = await client.GET('/devices')
      return requiredResponse(data, 'device list')
    },
  })
}

export function useDevice(deviceId: number, enabled = true) {
  const client = useApiClient()

  return useQuery({
    enabled,
    queryKey: queryKeys.devices.detail(deviceId),
    queryFn: async () => {
      const { data } = await client.GET('/devices/{device_id}', {
        params: { path: { device_id: deviceId } },
      })
      return requiredResponse(data, 'device')
    },
  })
}

export function useDeviceClients() {
  const client = useApiClient()

  return useQuery({
    queryKey: queryKeys.clients.all,
    queryFn: async () => {
      const { data } = await client.GET('/clients')
      return requiredResponse(data, 'VPN client list')
    },
  })
}

async function invalidateDeviceData(
  queryClient: ReturnType<typeof useQueryClient>,
) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: queryKeys.devices.all }),
    queryClient.invalidateQueries({ queryKey: queryKeys.clients.all }),
  ])
}

async function markDeviceDataStale(
  queryClient: ReturnType<typeof useQueryClient>,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      queryKey: queryKeys.devices.all,
      refetchType: 'none',
    }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.clients.all,
      refetchType: 'none',
    }),
  ])
}

export function useCreateDevice() {
  const client = useApiClient()
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (request: DeviceCreate) => {
      const { data } = await client.POST('/devices', { body: request })
      return requiredResponse(data, 'created device')
    },
    onSuccess: () => invalidateDeviceData(queryClient),
  })
}

interface UpdateDeviceRequest {
  deviceId: number
  update: DeviceUpdate
}

export function useUpdateDevice() {
  const client = useApiClient()
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ deviceId, update }: UpdateDeviceRequest) => {
      const { data } = await client.PATCH('/devices/{device_id}', {
        body: update,
        params: { path: { device_id: deviceId } },
      })
      return requiredResponse(data, 'updated device')
    },
    onSuccess: () => invalidateDeviceData(queryClient),
  })
}

export function useDeleteDevice() {
  const client = useApiClient()
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (deviceId: number) => {
      await client.DELETE('/devices/{device_id}', {
        params: { path: { device_id: deviceId } },
      })
    },
    onSuccess: () => markDeviceDataStale(queryClient),
  })
}

export function eligibleDeviceClients(
  clients: VpnClient[],
  devices: Device[],
  currentClientId?: number | null,
): VpnClient[] {
  const assigned = new Set(
    devices
      .map((device) => device.client_id)
      .filter(
        (clientId): clientId is number =>
          clientId !== null &&
          clientId !== undefined &&
          clientId !== currentClientId,
      ),
  )
  return clients.filter(
    (client) => client.id !== undefined && !assigned.has(client.id),
  )
}
