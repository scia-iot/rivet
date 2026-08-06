import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({
  useApiClient: vi.fn(),
}))

interface DeviceFixture {
  id: number
  name: string
  client_id: number | null
}

interface ClientFixture {
  id: number
  name: string
  revoked: boolean
}

let devices: DeviceFixture[]
let clients: ClientFixture[]

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  PATCH: vi.fn(),
  POST: vi.fn(),
}

function problem(status: number, detail: string) {
  return new ApiProblemError({
    type: `/errors/http-${status}`,
    title: status === 404 ? 'Not Found' : 'Conflict',
    status,
    detail,
  })
}

function deviceIdFromOptions(options: unknown): number {
  return (
    options as { params: { path: { device_id: number } } }
  ).params.path.device_id
}

function installSuccessfulApi() {
  apiClient.GET.mockImplementation(
    async (path: string, options?: unknown) => {
      if (path === '/devices') {
        return { data: devices }
      }
      if (path === '/clients') {
        return { data: clients }
      }
      if (path === '/devices/{device_id}') {
        const deviceId = deviceIdFromOptions(options)
        const device = devices.find(({ id }) => id === deviceId)
        if (device === undefined) {
          throw problem(404, `Device with ID ${deviceId} not found.`)
        }
        return { data: device }
      }
      throw new Error('Unexpected GET path in test.')
    },
  )
  apiClient.POST.mockImplementation(
    async (_path: string, options: unknown) => {
      const body = (
        options as {
          body: { name: string; client_id: number | null }
        }
      ).body
      const device = { id: 11, ...body }
      devices.push(device)
      return { data: device }
    },
  )
  apiClient.PATCH.mockImplementation(
    async (_path: string, options: unknown) => {
      const request = options as {
        body: { name?: string; client_id?: number | null }
        params: { path: { device_id: number } }
      }
      const device = devices.find(
        ({ id }) => id === request.params.path.device_id,
      )
      if (device === undefined) {
        throw problem(404, 'Device not found.')
      }
      Object.assign(device, request.body)
      return { data: device }
    },
  )
  apiClient.DELETE.mockImplementation(
    async (_path: string, options: unknown) => {
      const deviceId = deviceIdFromOptions(options)
      devices = devices.filter(({ id }) => id !== deviceId)
      return { data: undefined }
    },
  )
}

function renderDeviceRoute(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <PrincipalSessionProvider
          authenticationDisabled
          principal={null}
        >
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function chooseClient(
  user: ReturnType<typeof userEvent.setup>,
  name: string,
) {
  await user.click(
    screen.getByRole('combobox', { name: 'Current VPN client' }),
  )
  await user.click(await screen.findByText(name))
}

describe('device administration pages', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    devices = [
      { id: 7, name: 'Gateway', client_id: 2 },
      { id: 8, name: 'Unlinked sensor', client_id: null },
      { id: 9, name: 'Old gateway', client_id: 4 },
    ]
    clients = [
      { id: 2, name: 'gateway-client', revoked: false },
      { id: 3, name: 'available-client', revoked: false },
      { id: 4, name: 'revoked-client', revoked: true },
    ]
    installSuccessfulApi()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('lists IDs, names, current clients, and provisioning states', async () => {
    renderDeviceRoute('/devices')

    const table = await screen.findByRole('table', { name: 'Devices' })
    expect(within(table).getByText('7')).toBeVisible()
    expect(within(table).getByText('Gateway')).toBeVisible()
    expect(within(table).getByText('gateway-client')).toBeVisible()
    expect(within(table).getByText('Provisioned')).toBeVisible()
    expect(within(table).getByText('Unlinked sensor')).toBeVisible()
    expect(within(table).getByText('Not provisioned')).toBeVisible()
    expect(within(table).getByText('Client revoked')).toBeVisible()
  })

  it('creates an unlinked device with a searchable picker', async () => {
    const user = userEvent.setup()
    renderDeviceRoute('/devices/new')

    expect(
      await screen.findByRole('heading', { name: 'Create device' }),
    ).toBeVisible()
    await user.click(
      screen.getByRole('combobox', { name: 'Current VPN client' }),
    )
    expect(screen.queryByText('gateway-client')).not.toBeInTheDocument()
    expect(screen.queryByText('revoked-client')).not.toBeInTheDocument()
    const search = screen.getByRole('combobox', {
      name: 'Search VPN clients',
    })
    await user.type(search, 'available')
    expect(screen.getByText('available-client')).toBeVisible()
    await user.keyboard('{Escape}')

    await user.type(screen.getByLabelText('Device name'), 'New sensor')
    await user.click(screen.getByRole('button', { name: 'Create device' }))

    expect(
      await screen.findByRole('heading', { name: 'New sensor' }),
    ).toBeVisible()
    expect(screen.getByText('Not provisioned')).toBeVisible()
    expect(apiClient.POST).toHaveBeenCalledWith('/devices', {
      body: { name: 'New sensor', client_id: null },
    })
  })

  it('creates a device linked to an eligible client', async () => {
    const user = userEvent.setup()
    renderDeviceRoute('/devices/new')

    await screen.findByRole('heading', { name: 'Create device' })
    await user.type(screen.getByLabelText('Device name'), 'Linked sensor')
    await chooseClient(user, 'available-client')
    await user.click(screen.getByRole('button', { name: 'Create device' }))

    expect(
      await screen.findByRole('heading', { name: 'Linked sensor' }),
    ).toBeVisible()
    expect(screen.getByText('available-client')).toBeVisible()
    expect(apiClient.POST).toHaveBeenCalledWith('/devices', {
      body: { name: 'Linked sensor', client_id: 3 },
    })
  })

  it('rejects a whitespace-only device name inline', async () => {
    const user = userEvent.setup()
    renderDeviceRoute('/devices/new')

    const name = await screen.findByLabelText('Device name')
    await user.type(name, '   ')
    await user.click(screen.getByRole('button', { name: 'Create device' }))

    expect(await screen.findByText('Enter a device name.')).toBeVisible()
    expect(apiClient.POST).not.toHaveBeenCalled()
  })

  it('shows duplicate names as a correctable field error', async () => {
    const user = userEvent.setup()
    apiClient.POST.mockRejectedValue(
      problem(409, 'Device "Gateway" already exists.'),
    )
    renderDeviceRoute('/devices/new')

    const name = await screen.findByLabelText('Device name')
    await user.type(name, 'Gateway')
    await user.click(screen.getByRole('button', { name: 'Create device' }))

    expect(
      await screen.findByText('A device with this name already exists.'),
    ).toBeVisible()
    expect(name).toHaveValue('Gateway')
  })

  it.each([
    [
      'unknown client',
      problem(404, 'Client with ID 3 not found.'),
      'The selected VPN client no longer exists.',
    ],
    [
      'client assigned elsewhere',
      problem(409, 'Client with ID 3 is already assigned.'),
      'The selected VPN client is already assigned to another device.',
    ],
  ])('keeps edit state after %s failure', async (_label, error, message) => {
    const user = userEvent.setup()
    apiClient.PATCH.mockRejectedValue(error)
    renderDeviceRoute('/devices/7/edit')

    const name = await screen.findByLabelText('Device name')
    await user.clear(name)
    await user.type(name, 'Renamed gateway')
    await chooseClient(user, 'available-client')
    await user.click(screen.getByRole('button', { name: 'Save changes' }))

    expect(await screen.findByText(message)).toBeVisible()
    expect(name).toHaveValue('Renamed gateway')
    expect(
      screen.getByRole('combobox', { name: 'Current VPN client' }),
    ).toHaveTextContent('available-client')
    expect(
      screen.getByRole('heading', { name: 'Edit device' }),
    ).toBeVisible()
  })

  it('replaces and unlinks only after server success', async () => {
    const user = userEvent.setup()
    renderDeviceRoute('/devices/7/edit')

    expect(
      await screen.findByRole('combobox', { name: 'Current VPN client' }),
    ).toHaveTextContent('gateway-client')
    await chooseClient(user, 'available-client')
    expect(screen.queryByText('Provisioned')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save changes' }))

    expect(
      await screen.findByRole('heading', { name: 'Gateway' }),
    ).toBeVisible()
    expect(screen.getByText('available-client')).toBeVisible()

    await user.click(screen.getByRole('link', { name: 'Edit device' }))
    await chooseClient(user, 'No VPN client')
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByText('Not provisioned')).toBeVisible()
    expect(apiClient.PATCH).toHaveBeenLastCalledWith(
      '/devices/{device_id}',
      {
        body: { name: 'Gateway', client_id: null },
        params: { path: { device_id: 7 } },
      },
    )
  })

  it('renders a dedicated missing-device state', async () => {
    renderDeviceRoute('/devices/404')

    expect(
      await screen.findByRole('heading', { name: 'Device not found' }),
    ).toBeVisible()
    expect(screen.getByRole('link', { name: 'Back to devices' })).toBeVisible()
  })

  it('confirms deletion and states the client is untouched', async () => {
    const user = userEvent.setup()
    renderDeviceRoute('/devices/7')

    await screen.findByRole('heading', { name: 'Gateway' })
    await user.click(screen.getByRole('button', { name: 'Delete device' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent(
      'Deleting this device does not delete or revoke its VPN client.',
    )
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(apiClient.DELETE).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Delete device' }))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Delete device',
      }),
    )

    await waitFor(() => expect(apiClient.DELETE).toHaveBeenCalledOnce())
    expect(
      await screen.findByRole('heading', { name: 'Devices' }),
    ).toBeVisible()
  })

  it('keeps the current device visible when deletion fails', async () => {
    const user = userEvent.setup()
    apiClient.DELETE.mockRejectedValue(new Error('unsafe raw failure'))
    renderDeviceRoute('/devices/7')

    await screen.findByRole('heading', { name: 'Gateway' })
    await user.click(screen.getByRole('button', { name: 'Delete device' }))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Delete device',
      }),
    )

    expect(
      await screen.findByText('The action could not be completed. Try again.'),
    ).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByRole('heading', { name: 'Gateway' })).toBeVisible()
    expect(screen.queryByText('unsafe raw failure')).not.toBeInTheDocument()
  })
})
