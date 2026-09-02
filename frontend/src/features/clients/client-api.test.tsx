import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import { useImportClients } from '@/features/clients/client-api'

vi.mock('@/api/use-api-client', () => ({
  useApiClient: vi.fn(),
}))

const summary = {
  added: 1,
  updated: 2,
  clients_skipped: 3,
  devices_created: 4,
  devices_already_linked: 5,
  device_conflicts: 6,
}

const apiClient = {
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

describe('VPN client import mutation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiClient.POST.mockResolvedValue({ data: summary })
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('invalidates clients and only requested Device data', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const imported = renderHook(() => useImportClients(), {
      wrapper: createWrapper(queryClient),
    })

    await act(async () => {
      await imported.result.current.mutateAsync({ create_devices: false })
    })
    expect(apiClient.POST).toHaveBeenNthCalledWith(1, '/clients/import', {
      body: { create_devices: false },
    })
    expect(invalidate).toHaveBeenCalledTimes(1)
    expect(invalidate).toHaveBeenLastCalledWith({
      queryKey: queryKeys.clients.all,
    })

    invalidate.mockClear()
    await act(async () => {
      await imported.result.current.mutateAsync({ create_devices: true })
    })
    expect(apiClient.POST).toHaveBeenNthCalledWith(2, '/clients/import', {
      body: { create_devices: true },
    })
    expect(invalidate).toHaveBeenCalledTimes(2)
    expect(invalidate).toHaveBeenNthCalledWith(1, {
      queryKey: queryKeys.clients.all,
    })
    expect(invalidate).toHaveBeenNthCalledWith(2, {
      queryKey: queryKeys.devices.all,
    })
  })
})
