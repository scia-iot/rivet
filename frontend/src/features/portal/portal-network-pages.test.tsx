import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { ApiProblemError } from '@/api/problem-details'
import { useApiClient } from '@/api/use-api-client'
import { PrincipalSessionProvider } from '@/auth/principal-session'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))

const network = {
  id: 4,
  source_name: 'laptop',
  destination_name: 'edge-vpn',
  source_virtual_address: '10.8.0.2',
  destination_virtual_address: '10.8.0.3',
  private_network_addresses: '',
  start_time: '2026-10-28T08:00:00Z',
  end_time: null as string | null,
}
const api = { GET: vi.fn(), POST: vi.fn(), DELETE: vi.fn() }
let records: typeof network[]
let emptyInventory = false

function renderRoute(path = '/portal/networks') {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <PrincipalSessionProvider principal={{
          id: 1,
          display_name: 'User',
          issuer: 'issuer',
          subject: 'user',
          roles: ['device_user'],
          permissions: [],
        }}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return queryClient
}

async function create(actor: ReturnType<typeof userEvent.setup>) {
  await actor.click(screen.getByRole('button', { name: 'Create network' }))
  await actor.click(await screen.findByRole('combobox', {
    name: 'Source VPN client',
  }))
  expect(screen.getByRole('option', { name: /old-laptop/ })).toHaveAttribute(
    'aria-disabled', 'true',
  )
  await actor.click(screen.getByRole('option', { name: 'laptop' }))
  await actor.click(screen.getByRole('combobox', { name: 'Destination device' }))
  expect(screen.getByRole('option', { name: /Unprovisioned/ })).toHaveAttribute(
    'aria-disabled', 'true',
  )
  await actor.click(screen.getByRole('option', { name: 'Sensor' }))
  expect(screen.queryByLabelText('Private destinations')).not.toBeInTheDocument()
  await actor.click(screen.getByRole('button', {
    name: 'Create restricted network',
  }))
  await actor.click(screen.getByRole('button', { name: 'Confirm create' }))
}

describe('current-user restricted networks', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    records = []
    emptyInventory = false
    api.GET.mockImplementation(async (path: string) => {
      if (path === '/me/clients') {
        return { data: emptyInventory ? [] : [
          { id: 1, name: 'laptop', revoked: false },
          { id: 2, name: 'old-laptop', revoked: true },
        ] }
      }
      if (path === '/me/devices') {
        return { data: emptyInventory ? [] : [
          { id: 7, name: 'Sensor', client_id: 3 },
          { id: 8, name: 'Unprovisioned', client_id: null },
        ] }
      }
      if (path === '/me/networks') {
        return { data: records }
      }
      if (path === '/me/networks/{network_id}') {
        return { data: records[0] }
      }
      throw new Error(`Unexpected inventory request: ${path}`)
    })
    api.POST.mockImplementation(async () => {
      records = [network]
      return { data: network }
    })
    api.DELETE.mockImplementation(async () => {
      records = [{ ...network, end_time: '2026-10-28T09:00:00Z' }]
      return { data: undefined }
    })
    vi.mocked(useApiClient).mockReturnValue(
      api as unknown as ReturnType<typeof useApiClient>,
    )
  })

  it('creates, views and closes with scoped endpoints and query keys', async () => {
    const actor = userEvent.setup()
    const queries = renderRoute()
    expect(await screen.findByText('No restricted networks')).toBeVisible()
    await create(actor)
    expect(api.POST).toHaveBeenCalledWith('/me/networks', {
      body: { source_name: 'laptop', destination_device_id: 7 },
    })
    expect(await screen.findByRole('heading', {
      name: 'My network 4',
    })).toBeVisible()
    await actor.click(screen.getByRole('button', { name: 'Close network' }))
    await actor.click(screen.getByRole('button', { name: 'Confirm close' }))
    expect(await screen.findByText('Closed')).toBeVisible()
    expect(api.DELETE).toHaveBeenCalledWith('/me/networks/{network_id}', {
      params: { path: { network_id: 4 } },
    })
    expect(api.GET.mock.calls.every(([path]) => path.startsWith('/me/'))).toBe(true)
    expect(queries.getQueryCache().getAll().every(
      (query) => query.queryKey[0] === 'portal',
    )).toBe(true)
  })

  it.each([
    [403, /Access changed/],
    [409, /both clients have active credentials/],
    [412, /Both clients need assigned VPN addresses/],
    [503, /Retry the same request/],
  ])('shows safe remediation inside the failed modal (%s)', async (
    status, remediation,
  ) => {
    api.POST.mockRejectedValue(new ApiProblemError({
      type: '/errors/test',
      title: 'Private',
      status: status as number,
      detail: 'secret at 10.0.0.9',
    }))
    const actor = userEvent.setup()
    renderRoute()
    await screen.findByText('No restricted networks')
    await create(actor)
    const dialog = within(screen.getByRole('dialog'))
    expect(await dialog.findByText(
      'The action could not be completed. Try again.',
    )).toBeVisible()
    expect(dialog.getByText(remediation as RegExp)).toBeVisible()
    expect(screen.queryByText(/secret at/)).not.toBeInTheDocument()
    expect(dialog.getByRole('button', { name: 'Confirm create' })).toBeEnabled()
    expect(records).toEqual([])
  })

  it('retains active details when closing fails', async () => {
    records = [network]
    api.DELETE.mockRejectedValue(new Error('private host diagnostic'))
    const actor = userEvent.setup()
    renderRoute('/portal/networks/4')
    await actor.click(await screen.findByRole('button', { name: 'Close network' }))
    await actor.click(screen.getByRole('button', { name: 'Confirm close' }))
    expect(await screen.findByText(
      'The action could not be completed. Try again.',
    )).toBeVisible()
    expect(screen.getByText('Active')).toBeVisible()
    expect(screen.queryByText(/private host/)).not.toBeInTheDocument()
  })

  it('denies guessed records without revealing backend details', async () => {
    api.GET.mockRejectedValue(new ApiProblemError({
      type: '/errors/forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'other owner at 10.0.0.9',
    }))
    renderRoute('/portal/networks/999')
    expect(await screen.findByRole('heading', {
      name: 'Network unavailable',
    })).toBeVisible()
    expect(screen.queryByText(/other owner/)).not.toBeInTheDocument()
  })

  it('rejects invalid record IDs before fetching', async () => {
    renderRoute('/portal/networks/1e2')
    expect(await screen.findByRole('heading', {
      name: 'Network unavailable',
    })).toBeVisible()
    expect(api.GET).not.toHaveBeenCalled()
  })

  it('explains missing inventories and prevents creation', async () => {
    emptyInventory = true
    const actor = userEvent.setup()
    renderRoute()
    await actor.click(await screen.findByRole('button', { name: 'Create network' }))
    expect(await screen.findByText(
      /Ask an administrator to assign an active VPN client/,
    )).toBeVisible()
    expect(screen.getByText(/No devices granted/)).toBeVisible()
    expect(screen.getByRole('button', {
      name: 'Create restricted network',
    })).toBeDisabled()
  })

  it('offers a safe retry after list failures', async () => {
    api.GET.mockRejectedValue(new Error('private SQL detail'))
    const actor = userEvent.setup()
    renderRoute()
    expect(await screen.findByRole('heading', {
      name: 'Networks unavailable',
    })).toBeVisible()
    const calls = api.GET.mock.calls.length
    await actor.click(screen.getByRole('button', { name: 'Try again' }))
    await waitFor(() => expect(api.GET.mock.calls.length).toBeGreaterThan(calls))
    expect(screen.queryByText(/private SQL/)).not.toBeInTheDocument()
  })

  it('shows returned source-owned history', async () => {
    records = [network]
    renderRoute()
    const table = await screen.findByRole('table', { name: 'My networks' })
    expect(within(table).getByText('laptop')).toBeVisible()
    expect(within(table).getByText('edge-vpn')).toBeVisible()
  })
})
