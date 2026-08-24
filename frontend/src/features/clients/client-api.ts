import { useCallback } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type VpnClient = components['schemas']['Client']
export type VpnClientCreate = components['schemas']['ClientBase']
export type VpnClientDetails = components['schemas']['ClientDetails']
export type VirtualAddress = components['schemas']['VirtualAddress']
export type ClientImportSummary = components['schemas']['ClientImportSummary']

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function useClients() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.clients.all,
    queryFn: async () => {
      const { data } = await client.GET('/clients')
      return requiredResponse(data, 'VPN client list')
    },
  })
}

export function useClientDetails(clientName: string, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.clients.detail(clientName),
    queryFn: async () => {
      const { data } = await client.GET('/clients/{client_name}', {
        params: { path: { client_name: clientName } },
      })
      return requiredResponse(data, 'VPN client')
    },
  })
}

export function useAssignableAddresses(enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.clients.addresses,
    queryFn: async () => {
      const { data } = await client.GET(
        '/server/assignable-virtual-addresses',
      )
      return requiredResponse(data, 'assignable virtual address list')
    },
  })
}

async function invalidateAddressAssignment(
  queryClient: ReturnType<typeof useQueryClient>,
  clientName: string,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.clients.detail(clientName),
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.clients.addresses,
    }),
  ])
}

async function invalidateRevokedClient(
  queryClient: ReturnType<typeof useQueryClient>,
  clientName: string,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.clients.all,
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.clients.detail(clientName),
    }),
    queryClient.invalidateQueries({
      predicate: (query) =>
        query.queryKey.length === 3 &&
        query.queryKey[0] === 'users' &&
        query.queryKey[2] === 'clients',
    }),
  ])
}

export function useCreateClient() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (request: VpnClientCreate) => {
      const { data } = await client.POST('/clients', { body: request })
      return requiredResponse(data, 'created VPN client')
    },
    onSuccess: () =>
      queryClient.invalidateQueries({
        exact: true,
        queryKey: queryKeys.clients.all,
      }),
  })
}

export function useImportClients() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const { data } = await client.POST('/clients/import')
      return requiredResponse(data, 'VPN client import summary')
    },
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: queryKeys.clients.all }),
  })
}

export function useAssignVirtualAddress() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      clientName,
      ip,
    }: {
      clientName: string
      ip: string
    }) => {
      const { data } = await client.PUT(
        '/clients/{client_name}/assign-ip',
        {
          body: { ip },
          params: { path: { client_name: clientName } },
        },
      )
      return requiredResponse(data, 'updated VPN client')
    },
    onSuccess: (_data, request) =>
      invalidateAddressAssignment(queryClient, request.clientName),
  })
}

export function useUnassignVirtualAddress() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (clientName: string) => {
      await client.DELETE('/clients/{client_name}/unassign-ip', {
        params: { path: { client_name: clientName } },
      })
    },
    onSuccess: (_data, clientName) =>
      invalidateAddressAssignment(queryClient, clientName),
  })
}

export function useRenewCertificate() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (clientName: string) => {
      const { data } = await client.PUT(
        '/clients/{client_name}/renew-cert',
        { params: { path: { client_name: clientName } } },
      )
      return requiredResponse(data, 'renewed certificate')
    },
    onSuccess: (_data, clientName) =>
      queryClient.invalidateQueries({
        exact: true,
        queryKey: queryKeys.clients.detail(clientName),
      }),
  })
}

export function usePackageCertificate() {
  const client = useApiClient()
  return useMutation({
    mutationFn: async (clientName: string) => {
      await client.PUT('/clients/{client_name}/package-cert', {
        params: { path: { client_name: clientName } },
      })
    },
  })
}

export function useRevokeCertificate() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (clientName: string) => {
      const { data } = await client.PUT('/clients/{client_name}/revoke', {
        params: { path: { client_name: clientName } },
      })
      return requiredResponse(data, 'revoked VPN client')
    },
    onSuccess: (_data, clientName) =>
      invalidateRevokedClient(queryClient, clientName),
  })
}

function triggerArchiveDownload(archive: Blob, clientName: string) {
  const objectUrl = URL.createObjectURL(archive)
  const anchor = document.createElement('a')
  try {
    anchor.href = objectUrl
    anchor.download = `${clientName}.zip`
    anchor.hidden = true
    document.body.append(anchor)
    anchor.click()
  } finally {
    anchor.remove()
    URL.revokeObjectURL(objectUrl)
  }
}

export function useCertificateDownload() {
  const client = useApiClient()
  return useCallback(
    async (clientName: string) => {
      await client.PUT('/clients/{client_name}/package-cert', {
        params: { path: { client_name: clientName } },
      })
      const { data } = await client.GET(
        '/clients/{client_name}/download-cert',
        {
          params: { path: { client_name: clientName } },
          cache: 'no-store',
          parseAs: 'blob',
        },
      )
      if (!(data instanceof Blob)) {
        throw new Error('The certificate archive response was invalid.')
      }
      triggerArchiveDownload(data, clientName)
    },
    [client],
  )
}

export function certificateExpiryLabel(expiresOn: string): string {
  const date = new Date(expiresOn)
  if (Number.isNaN(date.valueOf())) {
    return 'Unavailable'
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}
