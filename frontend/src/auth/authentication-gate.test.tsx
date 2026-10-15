import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiProblemError } from '@/api/problem-details'
import { AuthenticationGate } from '@/auth/authentication-gate'

const state = vi.hoisted(() => ({
  signedIn: false,
  busy: false,
  principal: {
    data: undefined as unknown,
    error: null as unknown,
    isPending: false,
  },
}))

const authentication = vi.hoisted(() => ({
  signIn: vi.fn(async () => true),
  clearRedirectGuard: vi.fn(),
}))

vi.mock('@/auth/config', () => ({
  isAuthenticationDisabled: false,
  isE2EAuthenticationMode: false,
}))
vi.mock('@/auth/browser-authentication', () => ({
  useBrowserAuthentication: () => ({
    ready: state.signedIn && !state.busy,
    signedIn: state.signedIn,
    busy: state.busy,
    ...authentication,
  }),
}))
vi.mock('@/auth/current-principal', () => ({
  useCurrentPrincipal: () => state.principal,
}))

beforeEach(() => {
  sessionStorage.clear()
  state.signedIn = false
  state.busy = false
  state.principal = {
    data: undefined,
    error: null,
    isPending: false,
  }
  authentication.signIn.mockReset()
  authentication.signIn.mockResolvedValue(true)
  window.history.replaceState({}, '', '/users?tab=access')
})

describe('configured authentication gate', () => {
  it('stays signed out until the user explicitly starts login', async () => {
    const user = userEvent.setup()

    render(
      <AuthenticationGate>
        <p>Protected application</p>
      </AuthenticationGate>,
    )

    expect(screen.getByRole('heading', { name: 'Signed out' })).toBeVisible()
    expect(authentication.signIn).not.toHaveBeenCalled()
    expect(screen.queryByText('Protected application')).not.toBeInTheDocument()

    const signIn = screen.getByRole('button', { name: 'Sign in' })
    await user.click(signIn)
    expect(signIn).toBeDisabled()
    await user.click(signIn)

    expect(authentication.signIn).toHaveBeenCalledTimes(1)
  })

  it('does not redirect again when principal resolution remains unauthorized', async () => {
    state.signedIn = true
    state.principal = {
      data: undefined,
      error: new ApiProblemError({
        type: '/errors/unauthorized',
        title: 'Unauthorized',
        status: 401,
        detail: 'Authentication required.',
        instance: '/me',
      }),
      isPending: false,
    }
    authentication.signIn.mockResolvedValue(false)
    const view = render(
      <AuthenticationGate>
        <p>Protected application</p>
      </AuthenticationGate>,
    )

    await waitFor(() => expect(authentication.signIn).toHaveBeenCalledTimes(1))
    view.rerender(
      <AuthenticationGate><p>Protected application</p></AuthenticationGate>,
    )
    expect(authentication.signIn).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('heading', { name: 'Signing you in' })).toBeVisible()
  })
})
