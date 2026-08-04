import { createContext } from 'react'

import type { CurrentPrincipal } from '@/auth/current-principal'

export interface PrincipalSession {
  authenticationDisabled: boolean
  principal: CurrentPrincipal | null
}

export const PrincipalSessionContext =
  createContext<PrincipalSession | null>(null)
