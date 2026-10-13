import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import { queryKeys } from '@/api/query-keys'
import type { CurrentPrincipal } from '@/auth/current-principal'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const users = [
  {
    id: 7,
    display_name: 'Laptop User',
    issuer: 'https://login.example/tenant/v2.0',
    subject: 'stable-private-subject',
  },
  {
    id: 8,
    display_name: 'Second User',
    issuer: 'https://login.example/tenant/v2.0',
    subject: 'second-private-subject',
  },
]
const clients = [
  { id: 2, name: 'laptop-one', cidr: null, revoked: false },
  { id: 3, name: 'available-client', cidr: null, revoked: false },
  { id: 4, name: 'owned-elsewhere', cidr: null, revoked: false },
]
const devices = [
  { id: 11, name: 'Already authorized', client_id: null },
  { id: 12, name: 'Available edge device', client_id: null },
]
let userClients: Record<number, typeof clients>
let userDevices: Record<number, typeof devices>

const readOnlyPrincipal: CurrentPrincipal = {
  id: 19,
  display_name: 'Read only',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'read-only-subject',
  roles: [],
  permissions: ['users:read'],
}

const accessReadPrincipal: CurrentPrincipal = {
  id: 20,
  display_name: 'Access reader',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'access-reader-subject',
  roles: [],
  permissions: ['users:read', 'access:read'],
}

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  PATCH: vi.fn(),
  POST: vi.fn(),
  PUT: vi.fn(),
}

function problem(status: number) {
  return new ApiProblemError({
    type: `/errors/http-${status}`,
    title: status === 404 ? 'Not Found' : 'Conflict',
    status,
    detail: 'unsafe external identity detail',
  })
}

function userId(options: unknown): number {
  return (options as { params: { path: { user_id: number } } }).params.path
    .user_id
}

function installApi() {
  apiClient.GET.mockImplementation(async (path: string, options?: unknown) => {
    if (path === '/users') return { data: users }
    if (path === '/clients') return { data: clients }
    if (path === '/devices') return { data: devices }
    if (path === '/users/{user_id}') {
      const result = users.find((item) => item.id === userId(options))
      if (result === undefined) throw problem(404)
      return { data: result }
    }
    if (path === '/users/{user_id}/clients') {
      return { data: userClients[userId(options)] ?? [] }
    }
    if (path === '/users/{user_id}/devices') {
      return { data: userDevices[userId(options)] ?? [] }
    }
    throw new Error('Unexpected GET path.')
  })
  apiClient.POST.mockImplementation(async (path: string, options?: unknown) => {
    if (path !== '/users') throw new Error('Unexpected POST path.')
    const body = (options as { body: (typeof users)[number] }).body
    return { data: { ...body, id: 11 } }
  })
  apiClient.PATCH.mockImplementation(async (
    _path: string, options: unknown) => {
    const request = options as {
      body: { display_name: string }
      params: { path: { user_id: number } }
    }
    return {
      data: {
        ...users.find((item) => item.id === request.params.path.user_id),
        ...request.body,
      },
    }
  })
  apiClient.PUT.mockImplementation(async (path: string, options: unknown) => {
    if (path === '/users/{user_id}/clients/{client_id}') {
      const request = options as {
        params: { path: { user_id: number; client_id: number } }
      }
      const selected = clients.find(
        (item) => item.id === request.params.path.client_id,
      )
      if (selected !== undefined) {
        userClients[request.params.path.user_id].push(selected)
      }
      return { data: { id: 12, ...request.params.path } }
    }
    const request = options as {
      params: { path: { user_id: number; device_id: number } }
    }
    const selected = devices.find(
      (item) => item.id === request.params.path.device_id,
    )
    if (selected !== undefined) {
      userDevices[request.params.path.user_id].push(selected)
    }
    return { data: { id: 13, ...request.params.path } }
  })
  apiClient.DELETE.mockImplementation(async (
    path: string,
    options: unknown,
  ) => {
    if (path === '/users/{user_id}/devices/{device_id}') {
      const request = options as {
        params: { path: { user_id: number; device_id: number } }
      }
      const { device_id: deviceId, user_id: selectedUserId } =
        request.params.path
      userDevices[selectedUserId] = userDevices[selectedUserId].filter(
        (device) => device.id !== deviceId,
      )
    }
    return { data: undefined }
  })
}

function renderRoute(path: string, principal?: CurrentPrincipal) {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  })
  const result = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <PrincipalSessionProvider
          authenticationDisabled={principal === undefined}
          principal={principal ?? null}
        >
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { ...result, queryClient }
}

describe('user administration pages', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    userClients = { 7: [clients[0]], 8: [clients[2]] }
    userDevices = { 7: [devices[0]], 8: [] }
    installApi()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('lists users without external identity values', async () => {
    renderRoute('/users')
    const table = await screen.findByRole('table', { name: 'Users' })
    expect(within(table).getByText('Laptop User')).toBeVisible()
    expect(within(table).queryByText(users[0].issuer)).not.toBeInTheDocument()
    expect(within(table).queryByText(users[0].subject)).not.toBeInTheDocument()
  })

  it('creates a user and keeps duplicate identity errors safe', async () => {
    const actor = userEvent.setup()
    apiClient.POST.mockRejectedValueOnce(problem(409))
    renderRoute('/users/new')

    await actor.type(await screen.findByLabelText('Display name'), 'New User')
    await actor.type(screen.getByLabelText('Issuer'), 'issuer-value')
    await actor.type(screen.getByLabelText('Subject'), 'subject-value')
    await actor.click(screen.getByRole('button', { name: 'Create user' }))

    expect(
      await screen.findByText('This external identity is already registered.'),
    ).toBeVisible()
    expect(screen.queryByText('unsafe external identity detail')).not
      .toBeInTheDocument()
  })

  it('shows authorized devices without claiming ' +
    'network enforcement', async () => {
    const actor = userEvent.setup()
    renderRoute('/users/7')
    expect(await screen.findByText(users[0].issuer)).toBeVisible()
    expect(screen.getByText(users[0].subject)).toBeVisible()
    expect(screen.getByRole('tab', { name: 'Overview' })).toBeVisible()
    await actor.click(screen.getByRole('tab', { name: 'Device access' }))
    const table = await screen.findByRole('table', {
      name: 'Authorized devices',
    })
    expect(table).toHaveTextContent('Already authorized')
    expect(table).toHaveTextContent('Authorized')
    expect(table).toHaveTextContent('Not enforced')
    expect(
      screen.getByText(/application authorization only/i),
    ).toBeVisible()
    expect(
      screen.getByText(/does not apply OpenVPN or firewall policy/i),
    ).toBeVisible()
    expect(screen.getByText(/does not confirm network connectivity/i))
      .toBeVisible()

    await actor.click(screen.getByRole('combobox', { name: 'Device' }))
    const selector = screen.getByRole('dialog')
    expect(within(selector).getByRole('combobox', { name: 'Search devices' }))
      .toBeVisible()
    expect(within(selector).getByText('Available edge device')).toBeVisible()
    expect(within(selector).queryByText('Already authorized')).not
      .toBeInTheDocument()
    await actor.click(within(selector).getByText('Available edge device'))
  })

  it('grants and revokes only after backend confirmation', async () => {
    const actor = userEvent.setup()
    renderRoute('/users/7')
    await actor.click(
      await screen.findByRole('tab', { name: 'Device access' }),
    )
    await actor.click(screen.getByRole('combobox', { name: 'Device' }))
    await actor.click(screen.getByText('Available edge device'))
    await actor.click(screen.getByRole('button', { name: 'Grant access' }))

    const table = await screen.findByRole('table', {
      name: 'Authorized devices',
    })
    expect(
      await within(table).findByText('Available edge device'),
    ).toBeVisible()
    expect(apiClient.PUT).toHaveBeenCalledWith(
      '/users/{user_id}/devices/{device_id}',
      { params: { path: { user_id: 7, device_id: 12 } } },
    )

    await actor.click(
      within(table).getByRole('button', {
        name: 'Revoke access for Already authorized',
      }),
    )
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('application authorization record')
    await actor.click(
      within(dialog).getByRole('button', { name: 'Revoke access' }),
    )
    await waitFor(() => {
      expect(within(table).queryByText('Already authorized')).not
        .toBeInTheDocument()
    })
    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/users/{user_id}/devices/{device_id}',
      { params: { path: { user_id: 7, device_id: 11 } } },
    )
  })

  it('preserves visible authorization after failed mutations', async () => {
    const actor = userEvent.setup()
    apiClient.PUT.mockRejectedValueOnce(problem(404))
    apiClient.DELETE.mockRejectedValueOnce(problem(404))
    renderRoute('/users/7')
    await actor.click(
      await screen.findByRole('tab', { name: 'Device access' }),
    )
    const table = await screen.findByRole('table', {
      name: 'Authorized devices',
    })
    await actor.click(screen.getByRole('combobox', { name: 'Device' }))
    await actor.click(screen.getByText('Available edge device'))
    await actor.click(screen.getByRole('button', { name: 'Grant access' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The user or device no longer exists.',
    )
    expect(table).toHaveTextContent('Already authorized')
    expect(table).not.toHaveTextContent('Available edge device')

    await actor.click(
      within(table).getByRole('button', {
        name: 'Revoke access for Already authorized',
      }),
    )
    await actor.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Revoke access',
      }),
    )
    expect(
      await screen.findByText('The access grant no longer exists.'),
    ).toBeVisible()
    expect(table).toHaveTextContent('Already authorized')
  })

  it('separates access reading from grant controls', async () => {
    const actor = userEvent.setup()
    renderRoute('/users/7', accessReadPrincipal)
    await actor.click(
      await screen.findByRole('tab', { name: 'Device access' }),
    )
    expect(
      await screen.findByRole('table', { name: 'Authorized devices' }),
    ).toHaveTextContent('Already authorized')
    expect(screen.queryByRole('combobox', { name: 'Device' })).not
      .toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /revoke access for/i })).not
      .toBeInTheDocument()
    expect(apiClient.GET).not.toHaveBeenCalledWith(
      '/devices',
      expect.anything(),
    )
  })

  it('excludes clients owned elsewhere and ' + 'handles ownership conflicts', async () => {
    const actor = userEvent.setup()
    apiClient.PUT.mockRejectedValueOnce(problem(409))
    renderRoute('/users/7')
    await actor.click(await screen.findByRole('tab', { name: 'VPN clients' }))
    await actor.click(screen.getByRole('combobox', { name: 'VPN client' }))
    expect(screen.getByText('available-client')).toBeVisible()
    expect(screen.queryByText('owned-elsewhere')).not.toBeInTheDocument()
    await actor.click(screen.getByText('available-client'))
    await actor.click(screen.getByRole('button', { name: 'Assign client' }))
    expect(
      await screen.findByText('This VPN client is assigned to another user.'),
    ).toBeVisible()
  })

  it('unlinks without deleting or revoking the VPN client', async () => {
    const actor = userEvent.setup()
    renderRoute('/users/7')
    await actor.click(await screen.findByRole('tab', { name: 'VPN clients' }))
    await actor.click(await screen.findByRole('button', { name: 'Unlink' }))

    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/users/{user_id}/clients/{client_id}',
      { params: { path: { user_id: 7, client_id: 2 } } },
    )
    expect(apiClient.PUT).not.toHaveBeenCalledWith(
      '/clients/{client_name}/revoke',
      expect.anything(),
    )
  })

  it('renames a user with only the display name ' + 'in the PATCH body', async () => {
    const actor = userEvent.setup()
    const { queryClient } = renderRoute('/users/7/edit')
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const displayName = await screen.findByLabelText('Display name')
    await actor.clear(displayName)
    await actor.type(displayName, 'Renamed User')
    await actor.click(screen.getByRole('button', { name: 'Save name' }))

    expect(apiClient.PATCH).toHaveBeenCalledWith('/users/{user_id}', {
      body: { display_name: 'Renamed User' },
      params: { path: { user_id: 7 } },
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: ['current-principal'],
    })
  })

  it('adds a second client without replacing ' + 'an existing assignment', async () => {
    const actor = userEvent.setup()
    renderRoute('/users/7')
    await actor.click(await screen.findByRole('tab', { name: 'VPN clients' }))
    await actor.click(screen.getByRole('combobox', { name: 'VPN client' }))
    await actor.click(screen.getByText('available-client'))
    await actor.click(screen.getByRole('button', { name: 'Assign client' }))

    const table = await screen.findByRole('table', {
      name: 'User VPN clients',
    })
    expect(table).toHaveTextContent('laptop-one')
    expect(await within(table).findByText('available-client')).toBeVisible()
  })

  it('keeps read-only user data visible ' + 'without mutation controls', async () => {
    const actor = userEvent.setup()
    const list = renderRoute('/users', readOnlyPrincipal)
    expect(await screen.findByText('Laptop User')).toBeVisible()
    expect(
      screen.queryByRole('link', { name: 'Create user' }),
    ).not.toBeInTheDocument()
    list.unmount()

    renderRoute('/users/7', readOnlyPrincipal)
    expect(
      await screen.findByRole('heading', { name: 'Laptop User' }),
    ).toBeVisible()
    expect(screen.queryByText(users[0].issuer)).not.toBeInTheDocument()
    expect(screen.queryByText(users[0].subject)).not.toBeInTheDocument()
    expect(
      screen.queryByRole('link', { name: 'Rename user' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Delete user' }),
    ).not.toBeInTheDocument()
    await actor.click(screen.getByRole('tab', { name: 'VPN clients' }))
    expect(
      await screen.findByRole('table', { name: 'User VPN clients' }),
    ).toHaveTextContent('laptop-one')
    expect(screen.queryByLabelText('VPN client')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Assign client' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Unlink' }),
    ).not.toBeInTheDocument()
  })

  it('renders unknown users and safely deletes only the user', async () => {
    const missing = renderRoute('/users/404')
    expect(
      await screen.findByRole('heading', { name: 'User not found' }),
    ).toBeVisible()
    missing.unmount()

    const actor = userEvent.setup()
    const { queryClient } = renderRoute('/users/7')
    const invalidate = vi.spyOn(queryClient, 'invalidateQueries')
    const refetch = vi.spyOn(queryClient, 'refetchQueries')
    await actor.click(
      await screen.findByRole('button', { name: 'Delete user' }),
    )
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('VPN clients remain available')
    await actor.click(
      within(dialog).getByRole('button', { name: 'Delete user' }),
    )

    await waitFor(() => expect(apiClient.DELETE).toHaveBeenCalledOnce())
    expect(apiClient.DELETE).toHaveBeenCalledWith('/users/{user_id}', {
      params: { path: { user_id: 7 } },
    })
    expect(apiClient.DELETE).toHaveBeenCalledTimes(1)
    expect(apiClient.DELETE).not.toHaveBeenCalledWith(
      '/clients/{client_name}/unassign-ip',
      expect.anything(),
    )
    expect(apiClient.PUT).not.toHaveBeenCalledWith(
      '/clients/{client_name}/revoke',
      expect.anything(),
    )
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: ['users'],
      refetchType: 'none',
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: ['users', 7],
      refetchType: 'none',
    })
    expect(invalidate).toHaveBeenCalledWith({
      exact: true,
      queryKey: ['users', 7, 'clients'],
      refetchType: 'none',
    })
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: ['users', 'client-ownership'],
      refetchType: 'none',
    })
    expect(invalidate).not.toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: ['clients'] }),
    )
    expect(refetch).toHaveBeenCalledWith({
      exact: true,
      queryKey: ['users'],
      type: 'all',
    })
  })
  it('keys ownership data by the resolved set of users', () => {
    expect(queryKeys.users.clientOwnershipFor([7, 8])).not.toEqual(
      queryKeys.users.clientOwnershipFor([7]),
    )
  })

})
