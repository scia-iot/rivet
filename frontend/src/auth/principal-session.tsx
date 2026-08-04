import type { ReactNode } from 'react'

import { ApiProblemError } from '@/api/problem-details'
import type { CurrentPrincipal } from '@/auth/current-principal'
import { PrincipalSessionContext } from '@/auth/principal-session-context'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
export function PrincipalSessionProvider({
  authenticationDisabled = false,
  children,
  principal,
}: {
  authenticationDisabled?: boolean
  children: ReactNode
  principal: CurrentPrincipal | null
}) {
  return (
    <PrincipalSessionContext.Provider
      value={{ authenticationDisabled, principal }}
    >
      {children}
    </PrincipalSessionContext.Provider>
  )
}

export function ForbiddenLayout() {
  return (
    <main className="grid min-h-[60vh] place-items-center p-6">
      <section className="max-w-lg rounded-xl border bg-card p-6 shadow-sm">
        <h1 className="text-xl font-semibold">Access forbidden</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Your account does not have permission to view this area. Contact an
          administrator if you need access.
        </p>
      </section>
    </main>
  )
}

export function PrincipalErrorLayout({ error }: { error: unknown }) {
  if (error instanceof ApiProblemError && error.problem.status === 403) {
    return <ForbiddenLayout />
  }

  return (
    <main className="grid min-h-[60vh] place-items-center p-6">
      <section role="alert" className="max-w-lg rounded-xl border bg-card p-6 shadow-sm">
        <h1 className="text-xl font-semibold">Account unavailable</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          The signed-in account could not be resolved. Try signing in again or
          contact an administrator.
        </p>
      </section>
    </main>
  )
}

export function RequirePermission({
  children,
  permission,
}: {
  children: ReactNode
  permission: string
}) {
  const session = usePrincipalSession()
  if (!hasPermission(session, permission)) {
    return <ForbiddenLayout />
  }
  return children
}
