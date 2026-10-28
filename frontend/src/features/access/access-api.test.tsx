import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import {
  useGrantDeviceAccess,
  useBatchGrantDeviceAccess,
  useRevokeDeviceAccess,
  useUserDevices,
} from '@/features/access/access-api'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  PUT: vi.fn(),
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

describe('individual access API hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('loads user devices through the stable user-device key', async () => {
    const devices = [{ id: 4, name: 'Edge sensor', client_id: null }]
    apiClient.GET.mockResolvedValue({ data: devices })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    const result = renderHook(() => useUserDevices(7), {
      wrapper: createWrapper(queryClient),
    })

    await waitFor(() => expect(result.result.current.data).toEqual(devices))
    expect(apiClient.GET).toHaveBeenCalledWith('/users/{user_id}/devices', {
      params: { path: { user_id: 7 } },
    })
    expect(queryClient.getQueryData(queryKeys.users.devices(7))).toEqual(
      devices,
    )
  })

  it('refreshes user, device, and portal access after mutations', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.PUT.mockResolvedValue({
      data: { id: 9, user_id: 7, device_id: 4 },
    })
    apiClient.DELETE.mockResolvedValue({ data: undefined })

    const grant = renderHook(() => useGrantDeviceAccess(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await grant.result.current.mutateAsync({ userId: 7, deviceId: 4 })
    })

    const revoke = renderHook(() => useRevokeDeviceAccess(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await revoke.result.current.mutateAsync({ userId: 7, deviceId: 4 })
    })

    expect(apiClient.PUT).toHaveBeenCalledWith(
      '/users/{user_id}/devices/{device_id}',
      { params: { path: { user_id: 7, device_id: 4 } } },
    )
    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/users/{user_id}/devices/{device_id}',
      { params: { path: { user_id: 7, device_id: 4 } } },
    )
    expect(invalidate).toHaveBeenCalledTimes(8)
    expect(invalidate).toHaveBeenNthCalledWith(1, {
      exact: true,
      queryKey: queryKeys.users.devices(7),
    })
    expect(invalidate).toHaveBeenNthCalledWith(5, {
      exact: true,
      queryKey: queryKeys.users.devices(7),
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true, queryKey: queryKeys.devices.accessGrants(4),
    })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.portal.devices })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.portal.networks })
  })

  it('sends one batch and invalidates every distinct recipient', async () => {
    const queryClient = new QueryClient()
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.POST.mockResolvedValue({ data: { grants: [], created: 2, already_granted: 0 } })
    const batch = renderHook(() => useBatchGrantDeviceAccess(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await batch.result.current.mutateAsync({ deviceId: 4, userIds: [7, 8, 7] })
    })
    expect(apiClient.POST).toHaveBeenCalledWith('/devices/{device_id}/access-grants', {
      params: { path: { device_id: 4 } }, body: { user_ids: [7, 8, 7] },
    })
    for (const userId of [7, 8]) {
      expect(invalidate).toHaveBeenCalledWith({
        exact: true, queryKey: queryKeys.users.devices(userId),
      })
    }
    expect(invalidate).toHaveBeenCalledTimes(5)
  })

  it('preserves authorization state when a mutation fails', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const authorized = [{ id: 4, name: 'Edge sensor', client_id: null }]
    queryClient.setQueryData(queryKeys.users.devices(7), authorized)
    apiClient.PUT.mockRejectedValue(new Error('safe test failure'))

    const grant = renderHook(() => useGrantDeviceAccess(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await expect(
        grant.result.current.mutateAsync({ userId: 7, deviceId: 5 }),
      ).rejects.toThrow('safe test failure')
    })

    expect(invalidate).not.toHaveBeenCalled()
    expect(queryClient.getQueryData(queryKeys.users.devices(7))).toBe(
      authorized,
    )
  })
})
