import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'

import App from '@/App'
import { PrincipalSessionProvider } from '@/auth/principal-session'

describe('application shell', () => {
  it('renders the overview and primary navigation', () => {
    render(
      <MemoryRouter>
        <PrincipalSessionProvider authenticationDisabled principal={null}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>,
    )

    expect(
      screen.getByRole('heading', { name: 'Overview' }),
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Devices' })).toHaveAttribute(
      'href',
      '/devices',
    )
    expect(screen.getByText('Authentication disabled locally')).toBeVisible()
  })

  it('renders a feature placeholder route', () => {
    render(
      <MemoryRouter initialEntries={['/access']}>
        <PrincipalSessionProvider authenticationDisabled principal={null}>
          <App />
        </PrincipalSessionProvider>
      </MemoryRouter>,
    )

    expect(screen.getByRole('heading', { name: 'Access' })).toBeInTheDocument()
  })
})
