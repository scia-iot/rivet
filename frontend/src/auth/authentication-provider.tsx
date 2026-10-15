import type { ReactNode } from 'react'

import {
  e2eAccessToken,
  isAuthenticationDisabled,
  isAuthenticationConfigured,
  isE2EAuthenticationMode,
} from '@/auth/config'
import { BrowserAuthenticationContext } from '@/auth/browser-authentication'
import { EntraBrowserAuthenticationProvider } from '@/auth/entra-adapter'

export function AuthenticationProvider({ children }: { children: ReactNode }) {
  if (isAuthenticationDisabled || isE2EAuthenticationMode) {
    return (
      <BrowserAuthenticationContext.Provider value={{
        ready: true,
        signedIn: isE2EAuthenticationMode,
        busy: false,
        signIn: async () => false,
        signOut: async () => undefined,
        accessToken: async () => {
          if (e2eAccessToken === null) {
            throw new Error('A controlled E2E access token is required.')
          }
          return e2eAccessToken
        },
        clearRedirectGuard: () => undefined,
      }}>
        {children}
      </BrowserAuthenticationContext.Provider>
    )
  }

  if (!isAuthenticationConfigured) {
    return (
      <main className="grid min-h-svh place-items-center bg-muted/30 p-6">
        <section
          role="alert"
          className="max-w-lg rounded-xl border bg-card p-6 shadow-sm"
        >
          <h1 className="text-xl font-semibold">Authentication configuration required</h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Configure the Entra tenant, client ID, and API scope before serving
            this control panel. Authentication remains disabled only when
            VITE_AUTH_DISABLED=true is set explicitly for local development.
          </p>
        </section>
      </main>
    )
  }

  return <EntraBrowserAuthenticationProvider>{children}</EntraBrowserAuthenticationProvider>
}
