import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import type { components } from '@/api/generated/schema'
import { queryKeys } from '@/api/query-keys'
import { useApiClient } from '@/api/use-api-client'

export type User = components['schemas']['User']
export type UserCreate = components['schemas']['UserBase']
export type UserUpdate = components['schemas']['UserUpdate']
export type UserVpnClient = components['schemas']['Client']

export interface ClientOwnership {
  clientId: number
  userId: number
}

function requiredResponse<T>(data: T | undefined, entity: string): T {
  if (data === undefined) {
    throw new Error(`The ${entity} response was empty.`)
  }
  return data
}

export function useUsers() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.users.all,
    queryFn: async () => {
      const { data } = await client.GET('/users')
      return requiredResponse(data, 'user list')
    },
  })
}

export function useUser(userId: number, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.users.detail(userId),
    queryFn: async () => {
      const { data } = await client.GET('/users/{user_id}', {
        params: { path: { user_id: userId } },
      })
      return requiredResponse(data, 'user')
    },
  })
}

export function useUserClients(userId: number, enabled = true) {
  const client = useApiClient()
  return useQuery({
    enabled,
    queryKey: queryKeys.users.clients(userId),
    queryFn: async () => {
      const { data } = await client.GET('/users/{user_id}/clients', {
        params: { path: { user_id: userId } },
      })
      return requiredResponse(data, 'user VPN client list')
    },
  })
}

export function useAllUserClients(users: User[] | undefined) {
  const client = useApiClient()
  const userIds = (users ?? [])
    .flatMap((user) =>
      user.id === null || user.id === undefined ? [] : [user.id],
    )
    .sort((left, right) => left - right)
  return useQuery({
    enabled: users !== undefined,
    queryKey: queryKeys.users.clientOwnershipFor(userIds),
    queryFn: async () => {
      const records = await Promise.all(
        (users ?? []).flatMap((user) =>
          user.id === null || user.id === undefined
            ? []
            : [
                client
                  .GET('/users/{user_id}/clients', {
                    params: { path: { user_id: user.id } },
                  })
                  .then(({ data }) => ({
                    userId: user.id as number,
                    clients: requiredResponse(
                      data,
                      'user VPN client list',
                    ),
                  })),
              ],
        ),
      )
      return records.flatMap(({ userId, clients }) =>
        clients.flatMap((vpnClient) =>
          vpnClient.id === undefined
            ? []
            : [{ clientId: vpnClient.id, userId }],
        ),
      )
    },
  })
}

export function useUserClientChoices() {
  const client = useApiClient()
  return useQuery({
    queryKey: queryKeys.clients.all,
    queryFn: async () => {
      const { data } = await client.GET('/clients')
      return requiredResponse(data, 'VPN client list')
    },
  })
}

async function invalidateCreatedUserData(
  queryClient: ReturnType<typeof useQueryClient>,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.all,
    }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.users.clientOwnership,
    }),
  ])
}

async function invalidateRenamedUserData(
  queryClient: ReturnType<typeof useQueryClient>,
  userId: number,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.all,
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.detail(userId),
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.currentPrincipal.detail,
    }),
  ])
}

async function invalidateUserOwnership(
  queryClient: ReturnType<typeof useQueryClient>,
  userId: number,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.clients(userId),
    }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.users.clientOwnership,
    }),
  ])
}

async function markDeletedUserDataStale(
  queryClient: ReturnType<typeof useQueryClient>,
  userId: number,
) {
  await Promise.all([
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.all,
      refetchType: 'none',
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.detail(userId),
      refetchType: 'none',
    }),
    queryClient.invalidateQueries({
      exact: true,
      queryKey: queryKeys.users.clients(userId),
      refetchType: 'none',
    }),
    queryClient.invalidateQueries({
      queryKey: queryKeys.users.clientOwnership,
      refetchType: 'none',
    }),
  ])
  await queryClient.refetchQueries({
    exact: true,
    queryKey: queryKeys.users.all,
    type: 'all',
  })
}

export function useCreateUser() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (request: UserCreate) => {
      const { data } = await client.POST('/users', { body: request })
      return requiredResponse(data, 'created user')
    },
    onSuccess: () => invalidateCreatedUserData(queryClient),
  })
}

export function useUpdateUser() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      userId,
      update,
    }: {
      userId: number
      update: UserUpdate
    }) => {
      const { data } = await client.PATCH('/users/{user_id}', {
        body: update,
        params: { path: { user_id: userId } },
      })
      return requiredResponse(data, 'updated user')
    },
    onSuccess: (_data, request) =>
      invalidateRenamedUserData(queryClient, request.userId),
  })
}

export function useDeleteUser() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (userId: number) => {
      await client.DELETE('/users/{user_id}', {
        params: { path: { user_id: userId } },
      })
    },
    onSuccess: (_data, userId) =>
      markDeletedUserDataStale(queryClient, userId),
  })
}

export function useLinkUserClient() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      userId,
      clientId,
    }: {
      userId: number
      clientId: number
    }) => {
      await client.PUT('/users/{user_id}/clients/{client_id}', {
        params: { path: { user_id: userId, client_id: clientId } },
      })
    },
    onSuccess: (_data, request) =>
      invalidateUserOwnership(queryClient, request.userId),
  })
}

export function useUnlinkUserClient() {
  const client = useApiClient()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({
      userId,
      clientId,
    }: {
      userId: number
      clientId: number
    }) => {
      await client.DELETE('/users/{user_id}/clients/{client_id}', {
        params: { path: { user_id: userId, client_id: clientId } },
      })
    },
    onSuccess: (_data, request) =>
      invalidateUserOwnership(queryClient, request.userId),
  })
}
