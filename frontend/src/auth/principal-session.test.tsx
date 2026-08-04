import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'

import { ApiProblemError } from '@/api/problem-details'
import {
  PrincipalErrorLayout,
  PrincipalSessionProvider,
  RequirePermission,
} from '@/auth/principal-session'
import { AppShell } from '@/components/app-shell'

const principal = {
  id: 12,
  display_name: 'Alice',
  issuer: 'https://login.example/tenant/v2.0',
  subject: 'stable-subject',
  roles: ['sysadmin'],
  permissions: ['devices:read'],
}

describe('principal authorization presentation', () => {
  it('shows only navigation allowed by the trusted permissions', () => {
    render(
      <MemoryRouter>
        <PrincipalSessionProvider principal={principal}>
          <AppShell />
        </PrincipalSessionProvider>
      </MemoryRouter>,
    )

    expect(screen.getByRole('link', { name: 'Devices' })).toBeVisible()
    expect(screen.queryByRole('link', { name: 'Users' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Access' })).not.toBeInTheDocument()
  })

  it('renders forbidden for a direct route without permission', () => {
    render(
      <PrincipalSessionProvider principal={principal}>
        <RequirePermission permission="users:read">
          <p>User management</p>
        </RequirePermission>
      </PrincipalSessionProvider>,
    )

    expect(screen.getByRole('heading', { name: 'Access forbidden' })).toBeVisible()
    expect(screen.queryByText('User management')).not.toBeInTheDocument()
  })

  it('renders a forbidden state for a backend 403', () => {
    const error = new ApiProblemError({
      type: '/errors/forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'Not allowed.',
      instance: '/me',
    })

    render(<PrincipalErrorLayout error={error} />)

    expect(screen.getByRole('heading', { name: 'Access forbidden' })).toBeVisible()
    expect(screen.queryByText('Not allowed.')).not.toBeInTheDocument()
  })
})
