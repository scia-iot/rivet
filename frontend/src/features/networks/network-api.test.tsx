import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import {
  useCloseRestrictedNetwork,
  useCreateRestrictedNetwork,
  useRestrictedNetworks,
} from '@/features/networks/network-api'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
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

const network = {
  id: 4,
  source_name: 'laptop',
  source_virtual_address: '10.8.0.2',
  destination_name: 'gateway',
  destination_virtual_address: '10.8.0.3',
  private_network_addresses: '192.168.50.0/24',
  start_time: '2026-08-24T08:00:00Z',
  end_time: null,
}

describe('restricted-network API hooks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('loads every restricted network through the stable list key', async () => {
    apiClient.GET.mockResolvedValue({ data: [network] })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    const result = renderHook(() => useRestrictedNetworks(), {
      wrapper: createWrapper(queryClient),
    })

    await waitFor(() => expect(result.result.current.data).toEqual([network]))
    expect(apiClient.GET).toHaveBeenCalledWith('/networks')
    expect(queryClient.getQueryData(queryKeys.networks.all)).toEqual([network])
  })

  it('invalidates network data only after confirmed changes', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.POST.mockResolvedValue({ data: network })
    apiClient.DELETE.mockResolvedValue({ data: undefined })

    const created = renderHook(() => useCreateRestrictedNetwork(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await created.result.current.mutateAsync({
        source_name: 'laptop',
        destination_name: 'gateway',
        private_network_addresses: '192.168.50.0/24',
      })
    })

    const closed = renderHook(() => useCloseRestrictedNetwork(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await closed.result.current.mutateAsync(4)
    })

    expect(apiClient.POST).toHaveBeenCalledWith('/networks', {
      body: {
        source_name: 'laptop',
        destination_name: 'gateway',
        private_network_addresses: '192.168.50.0/24',
      },
    })
    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/networks/{network_id}',
      { params: { path: { network_id: 4 } } },
    )
    expect(invalidate).toHaveBeenNthCalledWith(1, {
      exact: true,
      queryKey: queryKeys.networks.all,
    })
    expect(invalidate).toHaveBeenNthCalledWith(2, {
      exact: true,
      queryKey: queryKeys.networks.all,
    })
    expect(invalidate).toHaveBeenNthCalledWith(3, {
      exact: true,
      queryKey: queryKeys.networks.detail(4),
    })
  })

  it('preserves active network data when close fails', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    queryClient.setQueryData(queryKeys.networks.detail(4), network)
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    apiClient.DELETE.mockRejectedValue(new Error('sensitive firewall failure'))

    const closed = renderHook(() => useCloseRestrictedNetwork(), {
      wrapper: createWrapper(queryClient),
    })
    await act(async () => {
      await expect(closed.result.current.mutateAsync(4)).rejects.toThrow(
        'sensitive firewall failure',
      )
    })

    expect(invalidate).not.toHaveBeenCalled()
    expect(queryClient.getQueryData(queryKeys.networks.detail(4))).toBe(network)
  })
})
