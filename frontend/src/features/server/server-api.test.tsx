import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import {
  SERVER_HEALTH_POLL_INTERVAL_MS,
  useAddServerRoute,
  useDeleteServerRoute,
  useInitializeServer,
  useServerHealth,
} from '@/features/server/server-api'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  POST: vi.fn(),
  PUT: vi.fn(),
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

function setVisibility(state: DocumentVisibilityState) {
  Object.defineProperty(document, 'visibilityState', {
    configurable: true,
    value: state,
  })
  document.dispatchEvent(new Event('visibilitychange'))
}

describe('server API hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
    setVisibility('visible')
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it(
    'polls health only while the document is visible and mounted',
    async () => {
    vi.useFakeTimers()
    apiClient.GET.mockResolvedValue({
      data: { status: 'active (running)', period: '15s' },
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    const result = renderHook(() => useServerHealth(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(apiClient.GET).toHaveBeenCalledTimes(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(SERVER_HEALTH_POLL_INTERVAL_MS)
    })
    expect(apiClient.GET).toHaveBeenCalledTimes(2)

    act(() => setVisibility('hidden'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SERVER_HEALTH_POLL_INTERVAL_MS * 2)
    })
    expect(apiClient.GET).toHaveBeenCalledTimes(2)

    act(() => setVisibility('visible'))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(apiClient.GET).toHaveBeenCalledTimes(3)

    result.unmount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(SERVER_HEALTH_POLL_INTERVAL_MS * 2)
    })
    expect(apiClient.GET).toHaveBeenCalledTimes(3)
  })

  it(
    'invalidates privileged data only after backend confirmation',
    async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.POST
      .mockResolvedValueOnce({ data: { port: '1194' } })
      .mockResolvedValueOnce({ data: undefined })
    apiClient.DELETE.mockResolvedValue({ data: undefined })

    const initialized = renderHook(() => useInitializeServer(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await initialized.result.current.mutateAsync({
        remote_host: 'vpn.example.test',
      })
    })

    const added = renderHook(() => useAddServerRoute(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await added.result.current.mutateAsync('192.168.40.0/24')
    })

    const deleted = renderHook(() => useDeleteServerRoute(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await deleted.result.current.mutateAsync('192.168.40.0/24')
    })

    expect(apiClient.POST).toHaveBeenNthCalledWith(1, '/server', {
      body: { remote_host: 'vpn.example.test' },
    })
    expect(apiClient.POST).toHaveBeenNthCalledWith(2, '/server/routes', {
      body: { network: '192.168.40.0/24' },
    })
    expect(apiClient.DELETE).toHaveBeenCalledWith('/server/routes', {
      params: { query: { network: '192.168.40.0/24' } },
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: queryKeys.server.all,
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: queryKeys.clients.addresses,
    })
    expect(invalidate).toHaveBeenCalledTimes(4)
  })

  it('preserves route data and does not invalidate after failure', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const routes = ['192.168.40.0/24 via 10.8.0.1']
    queryClient.setQueryData(queryKeys.server.routes, routes)
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.DELETE.mockRejectedValue(new Error('sensitive command failure'))

    const deleted = renderHook(() => useDeleteServerRoute(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await expect(
        deleted.result.current.mutateAsync('192.168.40.0/24'),
      ).rejects.toThrow('sensitive command failure')
    })

    expect(invalidate).not.toHaveBeenCalled()
    expect(queryClient.getQueryData(queryKeys.server.routes)).toBe(routes)
  })
})
