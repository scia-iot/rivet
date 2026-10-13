import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'
import {
  useDeleteClient,
  useImportClients,
} from '@/features/clients/client-api'

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
  DELETE: vi.fn(),
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
    apiClient.DELETE.mockResolvedValue({ data: undefined })
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


describe('VPN client deletion mutation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiClient.DELETE.mockResolvedValue({ data: undefined })
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('removes stale detail data and invalidates related collections', async () => {
    const queryClient = new QueryClient({
      defaultOptions: { mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const remove = vi.spyOn(queryClient, 'removeQueries')
    const deleted = renderHook(() => useDeleteClient(), {
      wrapper: createWrapper(queryClient),
    })

    await act(async () => {
      await deleted.result.current.mutateAsync('revoked-laptop')
    })

    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/clients/{client_name}',
      { params: { path: { client_name: 'revoked-laptop' } } },
    )
    expect(remove).toHaveBeenCalledWith({
      exact: true,
      queryKey: queryKeys.clients.detail('revoked-laptop'),
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: queryKeys.clients.all,
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: queryKeys.clients.addresses,
    })
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: queryKeys.devices.all,
    })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.users.all })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: queryKeys.portal.all })
  })
})
