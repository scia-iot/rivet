import { LogIn } from 'lucide-react'
import { type ReactNode, useState } from 'react'

import type { CurrentPrincipal } from '@/auth/current-principal'
import { PERMISSIONS } from '@/auth/permissions'
import { PrincipalSessionProvider } from '@/auth/principal-session'
import { Button } from '@/components/ui/button'

const CONTROLLED_ROLE_KEY = 'rivet:e2e:controlled-role'
const REDIRECT_RETURN_KEY = 'rivet:e2e:redirect-return'
const REDIRECT_RETURN_PATH = '/__e2e/auth-return'

type ControlledRole = 'device_user' | 'sysadmin'

function controlledRole(value: string | null): ControlledRole | null {
  return value === 'device_user' || value === 'sysadmin' ? value : null
}

function safeReturnPath(value: string | null): string {
  if (value === null || !value.startsWith('/') || value.startsWith('//')) {
    return '/'
  }
  return value
}

function resolveInitialRole(): ControlledRole | null {
  if (window.location.pathname !== REDIRECT_RETURN_PATH) {
    return controlledRole(window.sessionStorage.getItem(CONTROLLED_ROLE_KEY))
  }

  const returnPath = safeReturnPath(
    window.sessionStorage.getItem(REDIRECT_RETURN_KEY),
  )
  window.sessionStorage.removeItem(REDIRECT_RETURN_KEY)
  window.sessionStorage.setItem(CONTROLLED_ROLE_KEY, 'sysadmin')
  window.history.replaceState(null, '', returnPath)
  return 'sysadmin'
}

function principalFor(role: ControlledRole): CurrentPrincipal {
  return {
    id: role === 'sysadmin' ? 1 : 2,
    display_name:
      role === 'sysadmin' ? 'E2E administrator' : 'E2E device user',
    issuer: 'https://e2e.invalid',
    subject: role,
    roles: [role],
    permissions: role === 'sysadmin' ? [...PERMISSIONS] : [],
  }
}

function ControlledSignedOutLayout({ onSignIn }: { onSignIn: () => void }) {
  return (
    <main className="grid min-h-svh place-items-center bg-muted/30 p-6">
      <section className="max-w-lg rounded-xl border bg-card p-6 shadow-sm">
        <h1 className="text-xl font-semibold">Signed out</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Sign in to access the OpenVPN control panel.
        </p>
        <Button className="mt-4" onClick={onSignIn}>
          <LogIn aria-hidden="true" />
          Sign in
        </Button>
      </section>
    </main>
  )
}

/**
 * Provide deterministic identities only to the explicitly gated E2E dev mode.
 */
export function E2EAuthenticationGate({ children }: { children: ReactNode }) {
  const [role] = useState(resolveInitialRole)

  if (role === null) {
    return (
      <ControlledSignedOutLayout
        onSignIn={() => {
          const intendedPath = [
            window.location.pathname,
            window.location.search,
            window.location.hash,
          ].join('')
          window.sessionStorage.setItem(REDIRECT_RETURN_KEY, intendedPath)
          window.location.assign(REDIRECT_RETURN_PATH)
        }}
      />
    )
  }

  return (
    <PrincipalSessionProvider principal={principalFor(role)}>
      {children}
    </PrincipalSessionProvider>
  )
}
