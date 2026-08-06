import type { ReactNode } from 'react'

import { ApiProblemError } from '@/api/problem-details'
import type { CurrentPrincipal } from '@/auth/current-principal'
import { PrincipalSessionContext } from '@/auth/principal-session-context'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { ProblemAlert } from '@/components/shared/problem-alert'

const ACCOUNT_ERROR_DETAIL = [
  'The signed-in account could not be resolved.',
  'Try signing in again or contact an administrator.',
].join(' ')

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
      <div className="max-w-lg">
        <ProblemAlert
          problem={{
            type: '/errors/forbidden',
            title: 'Access forbidden',
            status: 403,
            detail: 'Your account does not have permission to view this area.',
          }}
        />
      </div>
    </main>
  )
}

export function PrincipalErrorLayout({ error }: { error: unknown }) {
  if (error instanceof ApiProblemError && error.problem.status === 403) {
    return <ForbiddenLayout />
  }

  return (
    <main className="grid min-h-[60vh] place-items-center p-6">
      <div className="max-w-lg">
        <ProblemAlert
          problem={{
            type: '/errors/account-unavailable',
            title: 'Account unavailable',
            status: 500,
            detail: ACCOUNT_ERROR_DETAIL,
          }}
        />
      </div>
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
