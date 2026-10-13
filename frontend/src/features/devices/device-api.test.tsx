import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import {
  useCreateDevice,
  useDeleteDevice,
  useUpdateDevice,
} from '@/features/devices/device-api'

vi.mock('@/api/use-api-client', () => ({
  useApiClient: vi.fn(),
}))

const apiClient = {
  DELETE: vi.fn(),
  PATCH: vi.fn(),
  POST: vi.fn(),
}

function createWrapper(queryClient: QueryClient) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    )
  }
}

describe('device mutations', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('invalidates device and client queries after mutations', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.POST.mockResolvedValue({
      data: { id: 7, name: 'Sensor', client_id: null },
    })
    apiClient.PATCH.mockResolvedValue({
      data: { id: 7, name: 'Sensor 2', client_id: 3 },
    })
    apiClient.DELETE.mockResolvedValue({ data: undefined })

    const created = renderHook(() => useCreateDevice(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await created.result.current.mutateAsync({
        name: 'Sensor',
        client_id: null,
      })
    })

    const updated = renderHook(() => useUpdateDevice(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await updated.result.current.mutateAsync({
        deviceId: 7,
        update: { name: 'Sensor 2', client_id: 3 },
      })
    })

    const deleted = renderHook(() => useDeleteDevice(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await deleted.result.current.mutateAsync(7)
    })

    expect(apiClient.POST).toHaveBeenCalledWith('/devices', {
      body: { name: 'Sensor', client_id: null },
    })
    expect(apiClient.PATCH).toHaveBeenCalledWith(
      '/devices/{device_id}',
      {
        body: { name: 'Sensor 2', client_id: 3 },
        params: { path: { device_id: 7 } },
      },
    )
    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/devices/{device_id}',
      { params: { path: { device_id: 7 } } },
    )
    expect(invalidate).toHaveBeenCalledTimes(6)
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: queryKeys.devices.all,
    })
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: queryKeys.clients.all,
    })
    expect(invalidate).toHaveBeenNthCalledWith(5, {
      queryKey: queryKeys.devices.all,
      refetchType: 'none',
    })
    expect(invalidate).toHaveBeenNthCalledWith(6, {
      queryKey: queryKeys.clients.all,
      refetchType: 'none',
    })
  })

  it('keeps cached assignment data after mutation failure', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const original = { id: 7, name: 'Sensor', client_id: 2 }
    queryClient.setQueryData(queryKeys.devices.detail(7), original)
    apiClient.PATCH.mockRejectedValue(new Error('safe test failure'))

    const updated = renderHook(() => useUpdateDevice(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await expect(
        updated.result.current.mutateAsync({
          deviceId: 7,
          update: { client_id: 3 },
        }),
      ).rejects.toThrow('safe test failure')
    })

    expect(invalidate).not.toHaveBeenCalled()
    expect(queryClient.getQueryData(queryKeys.devices.detail(7))).toBe(
      original,
    )
  })
})
