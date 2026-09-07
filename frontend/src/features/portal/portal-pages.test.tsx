import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import type { CurrentPrincipal } from '@/auth/current-principal'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const deviceUser: CurrentPrincipal = {
  id: 12,
  display_name: 'Edge operator',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'device-user-subject',
  roles: ['device_user'],
  permissions: [],
}

const ownedClient = {
  id: 7,
  name: 'laptop-one',
  revoked: false,
}
const revokedClient = {
  id: 8,
  name: 'old-laptop',
  revoked: true,
}
const grantedDevice = {
  id: 21,
  name: 'edge-sensor',
  client_id: 15,
}

const apiClient = {
  GET: vi.fn(),
  PUT: vi.fn(),
}

function deviceId(options: unknown): number {
  return (options as { params: { path: { device_id: number } } }).params.path
    .device_id
}

function installApi({ empty = false }: { empty?: boolean } = {}) {
  apiClient.GET.mockImplementation(async (path: string, options?: object) => {
    if (path === '/me/clients') {
      return { data: empty ? [] : [ownedClient, revokedClient] }
    }
    if (path === '/me/devices') {
      return { data: empty ? [] : [grantedDevice] }
    }
    if (path === '/me/devices/{device_id}') {
      const requestedId = deviceId(options)
      if (requestedId === 500) {
        throw new ApiProblemError({
          type: '/errors/internal',
          title: 'Private host failure',
          status: 500,
          detail: '/private/device?sig=secret-token',
        })
      }
      if (requestedId !== grantedDevice.id) {
        throw new ApiProblemError({
          type: '/errors/forbidden',
          title: 'Forbidden',
          status: 403,
          detail: 'Existing private device at 10.0.0.8.',
        })
      }
      return { data: grantedDevice }
    }
    if (path === '/me/clients/{client_name}/download-cert') {
      return { data: new Blob(['archive'], { type: 'application/zip' }) }
    }
    if (path === '/me/client-config') {
      return {
        data: new Blob(['client\nremote vpn.example.test'], {
          type: 'application/x-openvpn-profile',
        }),
      }
    }
    throw new Error(`Unexpected GET path: ${path}`)
  })
  apiClient.PUT.mockResolvedValue({ data: undefined })
}

function renderRoute(path: string) {
  const queryClient = new QueryClient({
    defaultOptions: {
      mutations: { retry: false },
      queries: { retry: false },
    },
  })
  const result = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <PrincipalSessionProvider principal={deviceUser}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { ...result, queryClient }
}

describe('device-user portal', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    sessionStorage.clear()
    installApi()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('lands device users in the portal without admin navigation', async () => {
    renderRoute('/')

    expect(
      await screen.findByRole('heading', { name: 'Device portal' }),
    ).toBeVisible()
    expect(screen.getByRole('link', { name: 'Portal' })).toBeVisible()
    expect(screen.getByRole('link', { name: 'My VPN clients' })).toBeVisible()
    expect(screen.getByRole('link', { name: 'My devices' })).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Users' })).not
      .toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Server' })).not
      .toBeInTheDocument()
  })

  it('forbids direct device-user navigation to admin routes', async () => {
    renderRoute('/users')

    expect(
      await screen.findByRole('heading', { name: 'Access forbidden' }),
    ).toBeVisible()
    expect(apiClient.GET).not.toHaveBeenCalledWith('/users')
  })

  it('shows only current-user clients and safe setup guidance', async () => {
    renderRoute('/portal/clients')

    const table = await screen.findByRole('table', {
      name: 'My VPN clients',
    })
    expect(within(table).getByText('laptop-one')).toBeVisible()
    expect(within(table).getByText('old-laptop')).toBeVisible()
    expect(screen.queryByText('another-user-client')).not.toBeInTheDocument()
    expect(
      screen.getByText(/keep the credential archive private/i),
    ).toBeVisible()
    expect(
      screen.getByText(/openvpn --config ovpncp-client\.ovpn --ca ca\.crt/),
    ).toBeVisible()
    expect(
      screen.getByText(/--cert <client-name>\.crt --key <client-name>\.key/),
    ).toBeVisible()
    expect(
      screen.queryByRole('button', {
        name: 'Download credentials for old-laptop',
      }),
    ).not.toBeInTheDocument()
  })

  it('separates granted authorization from network enforcement', async () => {
    renderRoute('/portal/devices')

    const table = await screen.findByRole('table', { name: 'My devices' })
    expect(within(table).getByText('edge-sensor')).toBeVisible()
    expect(within(table).getByText('Authorized')).toBeVisible()
    expect(within(table).getByText('Not enforced')).toBeVisible()
    expect(
      screen.getByText(/does not confirm network connectivity/i),
    ).toBeVisible()
  })

  it('shows granted device detail and hides denial diagnostics', async () => {
    const allowed = renderRoute('/portal/devices/21')
    expect(
      await screen.findByRole('heading', { name: 'edge-sensor' }),
    ).toBeVisible()
    expect(screen.getByText('Authorized')).toBeVisible()
    expect(screen.getByText('Not enforced')).toBeVisible()
    expect(screen.getByText(/connect using one of your active/i)).toBeVisible()

    allowed.unmount()
    renderRoute('/portal/devices/999')
    expect(
      await screen.findByRole('heading', { name: 'Device unavailable' }),
    ).toBeVisible()
    expect(screen.queryByText(/10\.0\.0\.8/)).not.toBeInTheDocument()
    expect(screen.queryByText(/does not exist/i)).not.toBeInTheDocument()
  })

  it('offers a safe retry for transient device-detail failures', async () => {
    const actor = userEvent.setup()
    renderRoute('/portal/devices/500')

    expect(
      await screen.findByRole('heading', {
        name: 'Device details unavailable',
      }),
    ).toBeVisible()
    expect(screen.queryByText(/private\/device/)).not.toBeInTheDocument()
    await actor.click(screen.getByRole('button', { name: 'Try again' }))
    const detailCalls = apiClient.GET.mock.calls.filter(
      ([path]) => path === '/me/devices/{device_id}',
    )
    expect(detailCalls).toHaveLength(2)
  })

  it('rejects non-canonical device IDs without an API request', async () => {
    renderRoute('/portal/devices/1e2')

    expect(
      await screen.findByRole('heading', { name: 'Device unavailable' }),
    ).toBeVisible()
    const detailCalls = apiClient.GET.mock.calls.filter(
      ([path]) => path === '/me/devices/{device_id}',
    )
    expect(detailCalls).toHaveLength(0)
  })

  it('cleans up owned credential downloads', async () => {
    const actor = userEvent.setup()
    const createObjectURL = vi.fn(() => 'blob:portal-short-lived')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL })
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    const beforeLocal = JSON.stringify(localStorage)
    const beforeSession = JSON.stringify(sessionStorage)
    const { queryClient } = renderRoute('/portal/clients')

    await actor.click(
      await screen.findByRole('button', {
        name: 'Download credentials for laptop-one',
      }),
    )

    expect(apiClient.PUT).toHaveBeenCalledWith(
      '/me/clients/{client_name}/package-cert',
      { params: { path: { client_name: 'laptop-one' } } },
    )
    expect(apiClient.GET).toHaveBeenCalledWith(
      '/me/clients/{client_name}/download-cert',
      {
        cache: 'no-store',
        params: { path: { client_name: 'laptop-one' } },
        parseAs: 'blob',
      },
    )
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(click).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:portal-short-lived')
    expect(document.querySelector('a[download="laptop-one.zip"]')).toBeNull()
    expect(JSON.stringify(localStorage)).toBe(beforeLocal)
    expect(JSON.stringify(sessionStorage)).toBe(beforeSession)
    expect(
      queryClient
        .getQueryCache()
        .getAll()
        .some((query) => query.state.data instanceof Blob),
    ).toBe(false)
  })

  it('downloads the shared profile once from connection setup', async () => {
    const actor = userEvent.setup()
    const createObjectURL = vi.fn(() => 'blob:shared-profile')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL })
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    renderRoute('/portal/clients')

    await actor.click(
      await screen.findByRole('button', {
        name: 'Download shared OpenVPN profile',
      }),
    )

    expect(apiClient.GET).toHaveBeenCalledWith('/me/client-config', {
      cache: 'no-store',
      parseAs: 'blob',
    })
    expect(apiClient.PUT).not.toHaveBeenCalled()
    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(click).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:shared-profile')
    expect(
      document.querySelector('a[download="ovpncp-client.ovpn"]'),
    ).toBeNull()
    expect(
      screen.getAllByRole('button', {
        name: 'Download shared OpenVPN profile',
      }),
    ).toHaveLength(1)
  })

  it('hides shared-profile failure details behind fixed guidance', async () => {
    const actor = userEvent.setup()
    const successfulGet = apiClient.GET.getMockImplementation()
    if (successfulGet === undefined) throw new Error('GET fixture unavailable.')
    apiClient.GET.mockImplementation(async (path: string, options?: object) => {
      if (path === '/me/client-config') {
        throw new Error('/private/profile.ovpn?token=sensitive')
      }
      return successfulGet(path, options)
    })
    renderRoute('/portal/clients')

    await actor.click(
      await screen.findByRole('button', {
        name: 'Download shared OpenVPN profile',
      }),
    )

    expect(
      await screen.findByText(
        /ask an administrator to verify the deployment configuration/i,
      ),
    ).toBeVisible()
    expect(screen.queryByText(/private\/profile/)).not.toBeInTheDocument()
  })

  it('renders empty states without assignments or grants', async () => {
    installApi({ empty: true })
    const clients = renderRoute('/portal/clients')
    expect(
      await screen.findByRole('heading', { name: 'No VPN clients assigned' }),
    ).toBeVisible()

    clients.unmount()
    renderRoute('/portal/devices')
    expect(
      await screen.findByRole('heading', { name: 'No devices authorized' }),
    ).toBeVisible()
  })

  it('renders fixed failures without backend details', async () => {
    apiClient.GET.mockRejectedValueOnce(
      new ApiProblemError({
        type: '/errors/internal',
        title: 'Archive path',
        status: 500,
        detail: '/private/archive.zip?sig=secret',
      }),
    )
    renderRoute('/portal/clients')

    expect(
      await screen.findByRole('heading', { name: 'VPN clients unavailable' }),
    ).toBeVisible()
    expect(screen.queryByText(/private\/archive/)).not.toBeInTheDocument()
  })
})
