import { createContext, useContext } from 'react'
import type { QueryClient } from '@tanstack/react-query'

export interface BrowserAuthentication {
  ready: boolean
  signedIn: boolean
  busy: boolean
  signIn(): Promise<boolean>
  signOut(queryClient: QueryClient): Promise<void>
  accessToken(): Promise<string>
  clearRedirectGuard(): void
}

export const BrowserAuthenticationContext = createContext<BrowserAuthentication | null>(null)

export function useBrowserAuthentication(): BrowserAuthentication {
  const authentication = useContext(BrowserAuthenticationContext)
  if (authentication === null) {
    throw new Error('Browser authentication provider is missing.')
  }
  return authentication
}
