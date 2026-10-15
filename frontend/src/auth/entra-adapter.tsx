import { InteractionStatus } from '@azure/msal-browser'
import { MsalProvider, useIsAuthenticated, useMsal } from '@azure/msal-react'
import { type ReactNode, useEffect, useMemo } from 'react'

import {
  BrowserAuthenticationContext,
  type BrowserAuthentication,
} from '@/auth/browser-authentication'
import { acquireAccessToken, msalInstance } from '@/auth/entra-client'
import {
  clearAuthenticationRedirectGuard,
  redirectForLogin,
  signOutAndClearSession,
} from '@/auth/redirect-coordinator'

function EntraContext({ children }: { children: ReactNode }) {
  const signedIn = useIsAuthenticated()
  const { accounts, inProgress, instance } = useMsal()
  const account = instance.getActiveAccount() ?? accounts[0]
  const ready = signedIn && account !== undefined && inProgress === InteractionStatus.None

  useEffect(() => {
    if (!signedIn || account === undefined) {
      return
    }
    if (instance.getActiveAccount()?.homeAccountId !== account.homeAccountId) {
      instance.setActiveAccount(account)
    }
  }, [account, signedIn, instance])

  const value = useMemo<BrowserAuthentication>(() => ({
    ready,
    signedIn,
    busy: inProgress !== InteractionStatus.None,
    signIn: () => redirectForLogin(instance),
    signOut: (queryClient) => signOutAndClearSession(
      instance, queryClient, instance.getActiveAccount(),
    ),
    accessToken: () => acquireAccessToken(instance, accounts),
    clearRedirectGuard: clearAuthenticationRedirectGuard,
  }), [accounts, inProgress, instance, ready, signedIn])

  return (
    <BrowserAuthenticationContext.Provider value={value}>
      {children}
    </BrowserAuthenticationContext.Provider>
  )
}

export function EntraBrowserAuthenticationProvider({ children }: { children: ReactNode }) {
  if (msalInstance === null) {
    throw new Error('Entra browser authentication is not configured.')
  }
  return (
    <MsalProvider instance={msalInstance}>
      <EntraContext>{children}</EntraContext>
    </MsalProvider>
  )
}
