import { InteractionStatus } from '@azure/msal-browser'
import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { LogIn } from 'lucide-react'
import { type ReactNode, useEffect, useState } from 'react'

import { ApiProblemError } from '@/api/problem-details'
import { useCurrentPrincipal } from '@/auth/current-principal'
import { isAuthenticationDisabled } from '@/auth/config'
import {
  clearAuthenticationRedirectGuard,
  redirectForLogin,
} from '@/auth/redirect-coordinator'
import {
  PrincipalErrorLayout,
  PrincipalSessionProvider,
} from '@/auth/principal-session'
import { Button } from '@/components/ui/button'

function AuthenticationStatusLayout({
  error = false,
  title,
}: {
  error?: boolean
  title: string
}) {
  return (
    <main className="grid min-h-svh place-items-center bg-muted/30 p-6">
      <section
        role={error ? 'alert' : 'status'}
        className="max-w-lg rounded-xl border bg-card p-6 shadow-sm"
      >
        <h1 className="text-xl font-semibold">{title}</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {error
            ? 'The sign-in flow could not be started. Refresh the page to try again.'
            : 'The control panel is securely resolving your account.'}
        </p>
      </section>
    </main>
  )
}

function UnauthenticatedLayout({
  loginPending,
  onSignIn,
  signInError,
}: {
  loginPending: boolean
  onSignIn: () => void
  signInError: boolean
}) {
  return (
    <main className="grid min-h-svh place-items-center bg-muted/30 p-6">
      <section
        role={signInError ? 'alert' : undefined}
        className="max-w-lg rounded-xl border bg-card p-6 shadow-sm"
      >
        <h1 className="text-xl font-semibold">Signed out</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {signInError
            ? 'Sign-in could not be started. Try again when you are ready.'
            : 'Sign in to access the OpenVPN control panel.'}
        </p>
        <Button className="mt-4" disabled={loginPending} onClick={onSignIn}>
          <LogIn aria-hidden="true" />
          {loginPending ? 'Redirecting' : 'Sign in'}
        </Button>
      </section>
    </main>
  )
}

function ConfiguredAuthenticationGate({ children }: { children: ReactNode }) {
  const authenticated = useIsAuthenticated()
  const { accounts, inProgress, instance } = useMsal()
  const [redirectError, setRedirectError] = useState(false)
  const [loginPending, setLoginPending] = useState(false)
  const account = instance.getActiveAccount() ?? accounts[0]
  const readyForPrincipal =
    authenticated && account !== undefined && inProgress === InteractionStatus.None
  const principal = useCurrentPrincipal(readyForPrincipal)

  async function startLogin(): Promise<void> {
    setRedirectError(false)
    setLoginPending(true)
    try {
      const started = await redirectForLogin(instance)
      if (!started) {
        setLoginPending(false)
      }
    } catch {
      setLoginPending(false)
      setRedirectError(true)
    }
  }

  useEffect(() => {
    if (!authenticated || account === undefined) {
      return
    }
    if (instance.getActiveAccount()?.homeAccountId !== account.homeAccountId) {
      instance.setActiveAccount(account)
    }
  }, [account, authenticated, instance])

  useEffect(() => {
    if (principal.data !== undefined) {
      clearAuthenticationRedirectGuard()
    }
  }, [principal.data])

  useEffect(() => {
    if (
      principal.error instanceof ApiProblemError &&
      principal.error.problem.status === 401
    ) {
      void redirectForLogin(instance).catch(() => setRedirectError(true))
    }
  }, [instance, principal.error])

  if (!authenticated && inProgress === InteractionStatus.None) {
    return (
      <UnauthenticatedLayout
        loginPending={loginPending}
        onSignIn={() => void startLogin()}
        signInError={redirectError}
      />
    )
  }

  if (redirectError) {
    return <AuthenticationStatusLayout error title="Sign-in unavailable" />
  }

  if (!readyForPrincipal) {
    return <AuthenticationStatusLayout title="Signing you in" />
  }

  if (principal.isPending) {
    return <AuthenticationStatusLayout title="Loading your account" />
  }

  if (principal.error !== null) {
    if (
      principal.error instanceof ApiProblemError &&
      principal.error.problem.status === 401
    ) {
      return <AuthenticationStatusLayout title="Signing you in" />
    }
    return <PrincipalErrorLayout error={principal.error} />
  }

  if (principal.data === undefined) {
    return <PrincipalErrorLayout error={new Error('Principal missing.')} />
  }

  return (
    <PrincipalSessionProvider principal={principal.data}>
      {children}
    </PrincipalSessionProvider>
  )
}

export function AuthenticationGate({ children }: { children: ReactNode }) {
  if (isAuthenticationDisabled) {
    return (
      <PrincipalSessionProvider
        authenticationDisabled
        principal={null}
      >
        {children}
      </PrincipalSessionProvider>
    )
  }
  return <ConfiguredAuthenticationGate>{children}</ConfiguredAuthenticationGate>
}
