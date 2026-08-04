import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { useCurrentPrincipal } from '@/auth/current-principal'

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }))

vi.mock('@/api/use-api-client', () => ({
  useApiClient: () => ({ GET: getMock }),
}))

function CurrentPrincipalProbe() {
  const principal = useCurrentPrincipal()
  return <p>{principal.data?.display_name ?? 'Loading'}</p>
}

describe('current principal query', () => {
  it('resolves the signed-in account through GET /me', async () => {
    getMock.mockResolvedValueOnce({
      data: {
        id: 12,
        display_name: 'Alice',
        issuer: 'https://login.example/tenant/v2.0',
        subject: 'stable-subject',
        roles: ['sysadmin'],
        permissions: ['devices:read'],
      },
    })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <CurrentPrincipalProbe />
      </QueryClientProvider>,
    )

    await waitFor(() => expect(screen.getByText('Alice')).toBeVisible())
    expect(getMock).toHaveBeenCalledWith('/me')
  })
})
