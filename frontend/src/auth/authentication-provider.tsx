import { MsalProvider } from '@azure/msal-react'
import type { ReactNode } from 'react'

import {
  isAuthenticationDisabled,
  msalInstance,
} from '@/auth/config'

export function AuthenticationProvider({ children }: { children: ReactNode }) {
  if (isAuthenticationDisabled) {
    return children
  }

  if (msalInstance === null) {
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

  return <MsalProvider instance={msalInstance}>{children}</MsalProvider>
}
