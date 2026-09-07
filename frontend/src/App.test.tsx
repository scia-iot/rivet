import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it, vi } from 'vitest'

import App from '@/App'
import { PrincipalSessionProvider } from '@/auth/principal-session'
vi.mock('@/features/clients/client-pages', () => ({
  ClientListPage: () => <h1>VPN clients</h1>,
  ClientDetailPage: () => null,
}))

describe('application shell', () => {
  it('lands local admins on VPN clients without empty navigation', async () => {
    render(
      <MemoryRouter>
        <PrincipalSessionProvider authenticationDisabled principal={null}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>,
    )

    expect(
      await screen.findByRole('heading', { name: 'VPN clients' }),
    ).toBeVisible()
    expect(screen.getByRole('link', { name: 'Devices' })).toHaveAttribute(
      'href',
      '/devices',
    )
    expect(screen.getByText('Authentication disabled locally')).toBeVisible()
    expect(
      screen.queryByRole('link', { name: 'Overview' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('link', { name: 'Access' }),
    ).not.toBeInTheDocument()
  })

  it('treats the removed Access route as not found', () => {
    render(
      <MemoryRouter initialEntries={['/access']}>
        <PrincipalSessionProvider authenticationDisabled principal={null}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('heading', { name: 'Page not found' }),
    ).toBeVisible()
    expect(
      screen.queryByRole('link', { name: 'Overview' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('link', { name: 'Access' }),
    ).not.toBeInTheDocument()
  })
})
