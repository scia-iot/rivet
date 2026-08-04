import { useContext } from 'react'

import {
  type PrincipalSession,
  PrincipalSessionContext,
} from '@/auth/principal-session-context'

export function usePrincipalSession(): PrincipalSession {
  const session = useContext(PrincipalSessionContext)
  if (session === null) {
    throw new Error('Principal session provider is required.')
  }
  return session
}

export function hasPermission(
  session: PrincipalSession,
  permission: string,
): boolean {
  return (
    session.authenticationDisabled ||
    session.principal?.permissions.includes(permission) === true
  )
}
