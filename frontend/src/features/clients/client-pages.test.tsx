import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import type { CurrentPrincipal } from '@/auth/current-principal'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const activeClient = {
  id: 2,
  name: 'laptop-one',
  cidr: null,
  revoked: false,
}
const revokedClient = {
  id: 3,
  name: 'revoked-laptop',
  cidr: null,
  revoked: true,
}
const clientDetails = {
  name: activeClient.name,
  cidr: null,
  revoked: false,
  virtual_address: { ip: '10.8.0.2' },
  cert: {
    issued_by: 'test-ca',
    issued_to: activeClient.name,
    issued_on: '2026-01-01T00:00:00Z',
    expires_on: '2027-01-01T00:00:00Z',
  },
  connections: [],
}

const readOnlyPrincipal: CurrentPrincipal = {
  id: 20,
  display_name: 'Client reader',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'client-reader-subject',
  roles: [],
  permissions: ['clients:read'],
}

const apiClient = {
  DELETE: vi.fn(),
  GET: vi.fn(),
  POST: vi.fn(),
  PUT: vi.fn(),
}

function problem(status: number) {
  return new ApiProblemError({
    type: `/errors/http-${status}`,
    title: status === 404 ? 'Not Found' : 'Operation failed',
    status,
    detail: '/server/private/archive.zip?sig=unsafe-token',
  })
}

function clientName(options: unknown): string {
  return (
    options as { params: { path: { client_name: string } } }
  ).params.path.client_name
}

function installApi() {
  apiClient.GET.mockImplementation(
    async (path: string, options?: { parseAs?: string } & object) => {
      if (path === '/clients') return { data: [activeClient, revokedClient] }
      if (path === '/server/assignable-virtual-addresses') {
        return { data: [{ id: 3, ip: '10.8.0.3', server_id: 1 }] }
      }
      if (path === '/clients/{client_name}') {
        if (clientName(options) === 'missing') throw problem(404)
        if (clientName(options) === revokedClient.name) {
          return {
            data: {
              ...clientDetails,
              name: revokedClient.name,
              revoked: true,
            },
          }
        }
        return { data: clientDetails }
      }
      if (path === '/clients/{client_name}/download-cert') {
        expect(options?.parseAs).toBe('blob')
        return { data: new Blob(['archive'], { type: 'application/zip' }) }
      }
      throw new Error('Unexpected GET path.')
    },
  )
  apiClient.POST.mockImplementation(async (path: string, options?: unknown) => {
    if (path === '/clients/import') return { data: { added: 1, updated: 2 } }
    const body = (options as { body: typeof activeClient }).body
    return { data: { ...body, id: 11 } }
  })
  apiClient.PUT.mockImplementation(async (path: string) => {
    if (path.endsWith('/assign-ip')) {
      return {
        data: { ...activeClient, virtual_address: { ip: '10.8.0.3' } },
      }
    }
    if (path.endsWith('/renew-cert')) return { data: clientDetails.cert }
    if (path.endsWith('/revoke')) {
      return { data: { ...activeClient, revoked: true } }
    }
    return { data: undefined }
  })
  apiClient.DELETE.mockResolvedValue({ data: undefined })
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

describe('VPN client administration pages', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    sessionStorage.clear()
    installApi()
    vi.mocked(useApiClient).mockReturnValue(
      apiClient as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('lists active and revoked clients ' + 'and creates or imports clients', async () => {
    const actor = userEvent.setup()
    renderRoute('/clients')
    const table = await screen.findByRole('table', { name: 'VPN clients' })
    expect(within(table).getByText('laptop-one')).toBeVisible()
    expect(within(table).getByText('Revoked')).toBeVisible()

    await actor.type(screen.getByLabelText('Client name'), 'new-laptop')
    await actor.click(screen.getByRole('button', { name: 'Create client' }))
    expect(apiClient.POST).toHaveBeenCalledWith('/clients', {
      body: { name: 'new-laptop', cidr: null, revoked: false },
    })

    await actor.click(screen.getByRole('button', { name: 'Import clients' }))
    expect(apiClient.POST).toHaveBeenCalledWith('/clients/import')
    expect(await screen.findByText(/1 added and 2 updated/i)).toBeVisible()
  })

  it('shows certificate expiry, revocation, and virtual address', async () => {
    const active = renderRoute('/clients/laptop-one')
    expect(
      await screen.findByRole('heading', { name: 'laptop-one' }),
    ).toBeVisible()
    expect(screen.getByText('Active')).toBeVisible()
    expect(screen.getByText(/Current address: 10.8.0.2/)).toBeVisible()
    expect(screen.getByText(/2027/)).toBeVisible()

    active.unmount()
    renderRoute('/clients/revoked-laptop')
    expect(await screen.findByText('Revoked')).toBeVisible()
  })
  it('keeps address selection after a virtual-address conflict', async () => {
    const actor = userEvent.setup()
    apiClient.PUT.mockRejectedValueOnce(problem(409))
    renderRoute('/clients/laptop-one')
    await actor.click(
      await screen.findByRole('combobox', { name: 'Virtual address' }),
    )
    await actor.click(screen.getByText('10.8.0.3'))
    await actor.click(screen.getByRole('button', { name: 'Assign address' }))

    expect(
      await screen.findByText(
        'This virtual address is assigned to another client.',
      ),
    ).toBeVisible()
    expect(
      screen.getByRole('combobox', { name: 'Virtual address' }),
    ).toHaveTextContent('10.8.0.3')
    expect(screen.queryByText(/private\/archive/)).not.toBeInTheDocument()
  })

  it('shows fixed certificate operation failures', async () => {
    const actor = userEvent.setup()
    apiClient.PUT.mockRejectedValueOnce(problem(500))
    renderRoute('/clients/laptop-one')
    await actor.click(await screen.findByRole('button', { name: 'Renew' }))
    expect(
      await screen.findByText(
        'The certificate could not be renewed. Try again.',
      ),
    ).toBeVisible()
    expect(screen.queryByText(/private\/archive/)).not.toBeInTheDocument()
  })

  it('requires the exact client name ' + 'and locks repeated revocation', async () => {
    const actor = userEvent.setup()
    let resolveRevoke: ((value: unknown) => void) | undefined
    apiClient.PUT.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveRevoke = resolve
        }),
    )
    renderRoute('/clients/laptop-one')
    await actor.click(
      await screen.findByRole('button', { name: 'Revoke certificate' }),
    )
    const dialog = screen.getByRole('dialog')
    const confirm = within(dialog).getByRole('button', {
      name: 'Revoke certificate',
    })
    expect(confirm).toBeDisabled()
    await actor.type(within(dialog).getByLabelText('Client name'), 'Laptop-one')
    expect(confirm).toBeDisabled()
    await actor.clear(within(dialog).getByLabelText('Client name'))
    await actor.type(within(dialog).getByLabelText('Client name'), 'laptop-one')
    await actor.dblClick(confirm)
    expect(apiClient.PUT).toHaveBeenCalledTimes(1)
    resolveRevoke?.({ data: { ...activeClient, revoked: true } })
    await waitFor(() =>
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument(),
    )
  })

  it('cleans up download URLs ' + 'and writes nothing to browser storage', async () => {
    const actor = userEvent.setup()
    const createObjectURL = vi.fn(() => 'blob:short-lived')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL,
      revokeObjectURL,
    })
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined)
    const beforeLocal = JSON.stringify(localStorage)
    const beforeSession = JSON.stringify(sessionStorage)
    const { queryClient } = renderRoute('/clients/laptop-one')

    await actor.click(
      await screen.findByRole('button', { name: 'Download' }),
    )
    expect(apiClient.PUT).toHaveBeenCalledWith(
      '/clients/{client_name}/package-cert',
      { params: { path: { client_name: 'laptop-one' } } },
    )
    expect(apiClient.GET).toHaveBeenCalledWith(
      '/clients/{client_name}/download-cert',
      {
        cache: 'no-store',
        params: { path: { client_name: 'laptop-one' } },
        parseAs: 'blob',
      },
    )
    const packageOrder = apiClient.PUT.mock.invocationCallOrder[0]
    const downloadOrder = apiClient.GET.mock.invocationCallOrder.at(-1)
    expect(packageOrder).toBeLessThan(downloadOrder as number)

    expect(createObjectURL).toHaveBeenCalledOnce()
    expect(click).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:short-lived')
    expect(
      document.querySelector('a[download="laptop-one.zip"]'),
    ).toBeNull()
    expect(JSON.stringify(localStorage)).toBe(beforeLocal)
    expect(JSON.stringify(sessionStorage)).toBe(beforeSession)
    expect(
      queryClient
        .getQueryCache()
        .getAll()
        .some((query) => query.state.data instanceof Blob),
    ).toBe(false)
  })

  it('renders a dedicated unknown-client state', async () => {
    renderRoute('/clients/missing')
    expect(
      await screen.findByRole('heading', { name: 'VPN client not found' }),
    ).toBeVisible()
  })

  it('clears a successful address selection ' + 'and unassigns explicitly', async () => {
    const actor = userEvent.setup()
    renderRoute('/clients/laptop-one')
    const selector = await screen.findByRole('combobox', {
      name: 'Virtual address',
    })
    await actor.click(selector)
    await actor.click(screen.getByText('10.8.0.3'))
    await actor.click(screen.getByRole('button', { name: 'Assign address' }))
    expect(selector).toHaveTextContent('Select an address')

    await actor.click(screen.getByRole('button', { name: 'Unassign address' }))
    expect(apiClient.DELETE).toHaveBeenCalledWith(
      '/clients/{client_name}/unassign-ip',
      { params: { path: { client_name: 'laptop-one' } } },
    )
  })

  it('shows read-only client data without mutation controls', async () => {
    const list = renderRoute('/clients', readOnlyPrincipal)
    const table = await screen.findByRole('table', { name: 'VPN clients' })
    expect(table).toHaveTextContent('laptop-one')
    expect(
      screen.queryByRole('button', { name: 'Import clients' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Client name')).not.toBeInTheDocument()
    list.unmount()

    renderRoute('/clients/laptop-one', readOnlyPrincipal)
    expect(await screen.findByText(/Current address:/)).toHaveTextContent(
      '10.8.0.2',
    )
    expect(screen.queryByLabelText('Virtual address')).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Assign address' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Unassign address' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Renew' })).not
      .toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Package' })).not
      .toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Download' })).not
      .toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Revoke certificate' }),
    ).not.toBeInTheDocument()
  })
})
