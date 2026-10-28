import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useApiClient } from '@/api/use-api-client'
import { PrincipalSessionProvider } from '@/auth/principal-session'
import type { Permission } from '@/auth/permissions'
import { DeviceUserAccess } from '@/features/access/device-user-access'

vi.mock('@/api/use-api-client', () => ({ useApiClient: vi.fn() }))
const api = { GET: vi.fn(), POST: vi.fn() }
let grants: { id: number; user_id: number; device_id: number }[]
const users = [1, 2, 3].map((id) => ({
  id,
  display_name: `User ${id}`,
  issuer: 'issuer',
  subject: String(id),
}))

function show(
  permissions: Permission[] = ['users:read', 'access:read', 'access:grant'],
) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <PrincipalSessionProvider
          principal={{
            id: 1,
            display_name: 'Admin',
            issuer: 'issuer',
            subject: 'admin',
            roles: ['sysadmin'],
            permissions,
          }}
        >
          {children}
        </PrincipalSessionProvider>
      </QueryClientProvider>
    )
  }
  return render(<DeviceUserAccess deviceId={4} />, { wrapper: Wrapper })
}

describe('device user access', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    grants = [{ id: 9, user_id: 1, device_id: 4 }]
    vi.mocked(useApiClient).mockReturnValue(
      api as unknown as ReturnType<typeof useApiClient>,
    )
    api.GET.mockImplementation(async (path: string) => ({
      data: path === '/users' ? users : grants,
    }))
    api.POST.mockResolvedValue({
      data: { grants: [], created: 2, already_granted: 0 },
    })
  })

  it('selects multiple eligible users and submits one batch', async () => {
    const user = userEvent.setup()
    show()
    expect(await screen.findByText('User 1 (ID 1)')).toBeInTheDocument()
    expect(
      screen.queryByRole('checkbox', { name: 'User 1 (ID 1)' }),
    ).not.toBeInTheDocument()
    for (const id of [2, 3]) {
      await user.click(
        screen.getByRole('checkbox', { name: `User ${id} (ID ${id})` }),
      )
    }
    expect(screen.getByText('2 of 100 users selected')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    await waitFor(() =>
      expect(api.POST).toHaveBeenCalledWith(
        '/devices/{device_id}/access-grants',
        {
          params: { path: { device_id: 4 } },
          body: { user_ids: [2, 3] },
        },
      ),
    )
    expect(await screen.findByRole('status')).toHaveTextContent(
      '2 granted; 0 already authorized.',
    )
  })

  it('locks pending requests and retains selection for safe retry', async () => {
    const user = userEvent.setup()
    let reject: (error: Error) => void = () => undefined
    api.POST.mockImplementationOnce(
      () => new Promise((_resolve, rejectPromise) => {
        reject = rejectPromise
      }),
    )
    show()
    await user.click(
      await screen.findByRole('checkbox', { name: 'User 2 (ID 2)' }),
    )
    await user.dblClick(screen.getByRole('button', { name: 'Grant access' }))
    expect(api.POST).toHaveBeenCalledTimes(1)
    expect(
      screen.getByRole('button', { name: 'Granting access…' }),
    ).toBeDisabled()
    await act(async () => reject(new Error('secret database detail')))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Access could not be granted. Try again.',
    )
    expect(screen.queryByText('secret database detail')).not.toBeInTheDocument()
    expect(
      screen.getByRole('checkbox', { name: 'User 2 (ID 2)' }),
    ).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2))
  })

  it('caps selection at 100 and allows correcting the selection', async () => {
    const choices = Array.from({ length: 101 }, (_, index) => ({
      ...users[0], id: index + 10, display_name: `Choice ${index}`,
    }))
    api.GET.mockImplementation(async (path: string) => ({
      data: path === '/users' ? choices : [],
    }))
    show()
    await screen.findByRole('checkbox', { name: 'Choice 0 (ID 10)' })
    const boxes = screen.getAllByRole('checkbox')
    for (const checkbox of boxes.slice(0, 100)) fireEvent.click(checkbox)
    expect(boxes[100]).toBeDisabled()
    expect(screen.getByText('100 of 100 users selected')).toBeInTheDocument()
    fireEvent.click(boxes[0])
    expect(boxes[100]).toBeEnabled()
  })

  it('shows search misses and resets selection when changing device', async () => {
    const user = userEvent.setup()
    const view = show()
    await user.click(
      await screen.findByRole('checkbox', { name: 'User 2 (ID 2)' }),
    )
    await user.type(screen.getByRole('textbox', { name: 'Search users' }), 'missing')
    expect(screen.getByText('No users match your search.')).toBeInTheDocument()
    view.rerender(<DeviceUserAccess deviceId={5} />)
    expect(await screen.findByText('0 of 100 users selected')).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'Search users' })).toHaveValue('')
  })

  it('shows a safe load error, retries, and handles an empty inventory', async () => {
    const user = userEvent.setup()
    api.GET.mockRejectedValueOnce(new Error('private detail'))
    show()
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'User access could not be loaded. Try again.',
    )
    expect(screen.queryByText('private detail')).not.toBeInTheDocument()
    grants = []
    api.GET.mockResolvedValue({ data: [] })
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByText('No additional users are available.')).toBeVisible()
    expect(screen.getByText('No users are authorized for this device.')).toBeVisible()
  })

  it('does not query inventories without access:read', () => {
    show(['users:read', 'access:grant'])
    expect(api.GET).not.toHaveBeenCalled()
    expect(
      screen.queryByRole('button', { name: 'Grant access' }),
    ).not.toBeInTheDocument()
  })

  it('shows grant IDs without fetching unauthorized user identities', async () => {
    show(['access:read', 'access:grant'])
    expect(await screen.findByText('User ID 1')).toBeInTheDocument()
    expect(api.GET).not.toHaveBeenCalledWith('/users')
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('allows review without mutation controls for access readers', async () => {
    show(['access:read', 'users:read'])
    expect(await screen.findByText('User 1 (ID 1)')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: 'Grant access' }),
    ).not.toBeInTheDocument()
    expect(api.POST).not.toHaveBeenCalled()
  })
})
