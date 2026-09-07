import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const server = {
  port: '1194',
  proto: 'udp',
  dev: 'tun0',
  topology: 'subnet',
  network_address: '10.8.0.0',
  subnet_mask: '255.255.255.0',
  ccd_exclusive: true,
  virtual_addresses: [
    { ip: '10.8.0.2' },
    { ip: '10.8.0.3' },
    { ip: '10.8.0.4' },
    { ip: '10.8.0.5' },
  ],
  key: '/secret/server.key',
}
const activeNetwork = {
  id: 4,
  source_name: 'laptop',
  source_virtual_address: '10.8.0.2',
  destination_name: 'gateway',
  destination_virtual_address: '10.8.0.3',
  private_network_addresses: '192.168.50.0/24',
  start_time: '2026-08-24T08:00:00Z',
  end_time: null as string | null,
}
const endedNetwork = {
  ...activeNetwork,
  id: 5,
  end_time: '2026-08-24T09:00:00Z',
}
let routes: string[]
let networks: Array<typeof activeNetwork>
let healthStatus: string

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  POST: vi.fn(),
}

function problem(status: number) {
  return new ApiProblemError({
    type: `/errors/http-${status}`,
    title: status === 404 ? 'Not Found' : 'Request failed',
    status,
    detail: 'Sensitive backend detail.',
  })
}

function networkId(options: unknown): number {
  return (
    options as { params: { path: { network_id: number } } }
  ).params.path.network_id
}

function installSuccessfulApi() {
  apiClient.GET.mockImplementation(async (path: string, options?: unknown) => {
    if (path === '/server') return { data: server }
    if (path === '/server/health') {
      return { data: { status: healthStatus, period: '15s' } }
    }
    if (path === '/server/assignable-virtual-addresses') {
      return {
        data: [
          { id: 2, ip: '10.8.0.4', server_id: 1 },
          { id: 3, ip: '10.8.0.5', server_id: 1 },
        ],
      }
    }
    if (path === '/server/routes') return { data: routes }
    if (path === '/clients') {
      return {
        data: [
          { id: 1, name: 'laptop', revoked: false },
          { id: 2, name: 'gateway', revoked: false },
        ],
      }
    }
    if (path === '/networks') return { data: networks }
    if (path === '/networks/{network_id}') {
      const match = networks.find(({ id }) => id === networkId(options))
      if (match === undefined) throw problem(404)
      return { data: match }
    }
    throw new Error('Unexpected GET path in Phase 7 test.')
  })
  apiClient.POST.mockImplementation(async (path: string, options?: unknown) => {
    if (path === '/server/routes') {
      const network = (options as { body: { network: string } }).body.network
      routes.push(`${network} via 10.8.0.1`)
      return { data: undefined }
    }
    if (path === '/networks') {
      const body = (
        options as {
          body: {
            source_name: string
            destination_name: string
            private_network_addresses: string
          }
        }
      ).body
      const created = {
        id: 6,
        source_virtual_address: '10.8.0.2',
        destination_virtual_address: '10.8.0.3',
        start_time: '2026-08-24T10:00:00Z',
        end_time: null,
        ...body,
      }
      networks.push(created)
      return { data: created }
    }
    if (path === '/server') return { data: server }
    throw new Error('Unexpected POST path in Phase 7 test.')
  })
  apiClient.DELETE.mockImplementation(
    async (path: string, options?: unknown) => {
      if (path === '/server/routes') {
        const network = (
          options as { params: { query: { network: string } } }
        ).params.query.network
        routes = routes.filter((route) => !route.startsWith(`${network} `))
        return { data: undefined }
      }
      if (path === '/networks/{network_id}') {
        const match = networks.find(({ id }) => id === networkId(options))
        if (match === undefined) throw problem(404)
        match.end_time = '2026-08-24T11:00:00Z'
        return { data: undefined }
      }
      throw new Error('Unexpected DELETE path in Phase 7 test.')
    },
  )
}

function renderRoute(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <PrincipalSessionProvider authenticationDisabled principal={null}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function selectEntity(
  user: ReturnType<typeof userEvent.setup>,
  label: string,
  option: string,
) {
  await user.click(screen.getByRole('combobox', { name: label }))
  await user.click(await screen.findByRole('option', { name: option }))
}

describe('server and network administration pages', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    routes = ['192.168.20.0/24 via 10.8.0.1']
    networks = [activeNetwork, endedNetwork].map((network) => ({ ...network }))
    healthStatus = 'active (running)'
    installSuccessfulApi()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it(
    'shows health, a safe configuration summary, and assignable addresses',
    async () => {
    renderRoute('/server')

    expect(await screen.findByText('active (running)')).toBeVisible()
    expect(screen.getByText('UDP')).toBeVisible()
    expect(screen.getByText('10.8.0.0 / 255.255.255.0')).toBeVisible()
    const summary = screen.getByLabelText('Virtual address summary')
    expect(summary).toHaveTextContent('Total4')
    expect(summary).toHaveTextContent('Assigned2')
    expect(summary).toHaveTextContent('Available2')
    expect(
      screen.getByLabelText('Assignable virtual addresses'),
    ).toHaveTextContent('10.8.0.4, 10.8.0.5')
    expect(
      screen.queryByRole('table', { name: 'Assignable virtual addresses' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('/secret/server.key')).not.toBeInTheDocument()
  })

  it('shows an explicit empty assignable-address state', async () => {
    const successfulGet = apiClient.GET.getMockImplementation()
    if (successfulGet === undefined) throw new Error('GET fixture unavailable.')
    apiClient.GET.mockImplementation(async (path: string, options?: unknown) => {
      if (path === '/server/assignable-virtual-addresses') return { data: [] }
      return successfulGet(path, options)
    })
    renderRoute('/server')

    expect(
      await screen.findByRole('heading', {
        name: 'No assignable virtual addresses',
      }),
    ).toBeVisible()
    const summary = screen.getByLabelText('Virtual address summary')
    expect(summary).toHaveTextContent('Total4')
    expect(summary).toHaveTextContent('Assigned4')
    expect(summary).toHaveTextContent('Available0')
    expect(screen.getByText('Every address is assigned or the pool is empty.'))
      .toBeVisible()
  })

  it('shows a retryable address-list error without partial content', async () => {
    const successfulGet = apiClient.GET.getMockImplementation()
    if (successfulGet === undefined) throw new Error('GET fixture unavailable.')
    apiClient.GET.mockImplementation(async (path: string, options?: unknown) => {
      if (path === '/server/assignable-virtual-addresses') throw problem(500)
      return successfulGet(path, options)
    })
    renderRoute('/server')

    expect(await screen.findByText('Server data unavailable')).toBeVisible()
    expect(
      screen.queryByLabelText('Assignable virtual addresses'),
    ).not.toBeInTheDocument()
  })

  it('presents inactive health as a negative state', async () => {
    healthStatus = 'inactive (dead)'
    renderRoute('/server')

    expect(await screen.findByText('inactive (dead)')).toHaveClass(
      'bg-red-50',
    )
  })

  it(
    'shows a safe retry state when cached health refresh fails',
    async () => {
      const user = userEvent.setup()
      const successfulGet = apiClient.GET.getMockImplementation()
      if (successfulGet === undefined) {
        throw new Error('The successful GET fixture is unavailable.')
      }
      let healthCalls = 0
      apiClient.GET.mockImplementation(async (path: string, options?: unknown) => {
        if (path !== '/server/health') {
          return successfulGet(path, options)
        }
        healthCalls += 1
        if (healthCalls === 2) {
          throw new Error('health failure at 10.8.0.1')
        }
        return { data: { status: 'active (running)', period: '15s' } }
      })
      renderRoute('/server')
      expect(await screen.findByText('active (running)')).toBeVisible()

      await act(async () => {
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          value: 'hidden',
        })
        document.dispatchEvent(new Event('visibilitychange'))
      })
      await act(async () => {
        Object.defineProperty(document, 'visibilityState', {
          configurable: true,
          value: 'visible',
        })
        document.dispatchEvent(new Event('visibilitychange'))
      })

      expect(
        await screen.findByText('OpenVPN health refresh failed'),
      ).toBeVisible()
      expect(
        screen.getByText(
          'The last health report may be stale. Check the host service and retry.',
        ),
      ).toBeVisible()
      expect(screen.queryByText('health failure at 10.8.0.1'))
        .not.toBeInTheDocument()

      await user.click(screen.getByRole('button', { name: 'Try again' }))
      await waitFor(() => {
        expect(
          screen.queryByText('OpenVPN health refresh failed'),
        ).not.toBeInTheDocument()
      })
      expect(healthCalls).toBe(3)
    },
  )

  it(
    'validates and confirms route changes, then presents safe retry',
    async () => {
    const user = userEvent.setup()
    renderRoute('/server/routes')

    const input = await screen.findByLabelText('Private network')
    await user.type(input, 'not-a-route')
    expect(
      screen.getByText('Enter a valid private IPv4 network in CIDR notation.'),
    ).toBeVisible()
    expect(screen.getByRole('button', { name: 'Add route' })).toBeDisabled()

    await user.clear(input)
    await user.type(input, '192.168.40.0/24')
    apiClient.POST.mockRejectedValueOnce(
      new Error('command failed for 192.168.40.0/24'),
    )
    await user.click(screen.getByRole('button', { name: 'Add route' }))
    let dialog = screen.getByRole('dialog')
    await user.click(
      within(dialog).getByRole('button', { name: 'Confirm add' }),
    )
    expect(
      await within(dialog).findByText(
        'The action could not be completed. Try again.',
      ),
    ).toBeVisible()
    expect(dialog).not.toHaveTextContent('command failed')

    await user.click(
      within(dialog).getByRole('button', { name: 'Confirm add' }),
    )
    await waitFor(() => expect(apiClient.POST).toHaveBeenCalledTimes(2))
    expect(
      await screen.findByText('192.168.40.0/24 via 10.8.0.1'),
    ).toBeVisible()
  })

  it(
    'lists and creates restricted networks after firewall confirmation',
    async () => {
    const user = userEvent.setup()
    renderRoute('/networks')

    const table = await screen.findByRole('table', {
      name: 'Restricted networks',
    })
    expect(within(table).getAllByText('laptop')).toHaveLength(2)
    expect(within(table).getByText('Active')).toBeVisible()
    expect(within(table).getByText('Ended', { selector: 'span' })).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Create network' }))
    await selectEntity(user, 'Source VPN client', 'laptop')
    await selectEntity(user, 'Destination VPN client', 'gateway')
    await user.type(
      screen.getByLabelText('Private destinations'),
      '192.168.60.0/24',
    )
    await user.click(
      screen.getByRole('button', { name: 'Create restricted network' }),
    )
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('firewall')
    await user.click(
      within(dialog).getByRole('button', { name: 'Confirm create' }),
    )

    expect(
      await screen.findByRole('heading', { name: 'Restricted network 6' }),
    ).toBeVisible()
    expect(apiClient.POST).toHaveBeenCalledWith('/networks', {
      body: {
        source_name: 'laptop',
        destination_name: 'gateway',
        private_network_addresses: '192.168.60.0/24',
      },
    })
  })

  it('renders missing and already-ended network states', async () => {
    const missing = renderRoute('/networks/404')
    expect(
      await screen.findByRole('heading', {
        name: 'Restricted network not found',
      }),
    ).toBeVisible()
    missing.unmount()

    renderRoute('/networks/5')
    expect(await screen.findByText('Ended')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Close network' }))
      .not.toBeInTheDocument()
  })

  it(
    'keeps an active network open after a failed close and allows retry',
    async () => {
    const user = userEvent.setup()
    apiClient.DELETE.mockRejectedValueOnce(
      new Error('firewall 10.8.0.2 command failed'),
    )
    renderRoute('/networks/4')

    expect(await screen.findByText('Active')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Close network' }))
    let dialog = screen.getByRole('dialog')
    await user.click(
      within(dialog).getByRole('button', { name: 'Confirm close' }),
    )
    expect(
      await within(dialog).findByText(
        'The action could not be completed. Try again.',
      ),
    ).toBeVisible()
    expect(screen.getByText('Active')).toBeVisible()
    expect(dialog).not.toHaveTextContent('10.8.0.2 command failed')

    await user.click(
      within(dialog).getByRole('button', { name: 'Confirm close' }),
    )
    expect(await screen.findByText('Ended')).toBeVisible()
  })
})
