import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { useQueryClient } from '@tanstack/react-query'
import { LogIn, LogOut } from 'lucide-react'
import { useState } from 'react'

import {
  isAuthenticationConfigured,
  isAuthenticationDisabled,
} from '@/auth/config'
import {
  redirectForLogin,
  signOutAndClearSession,
} from '@/auth/redirect-coordinator'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

function ConfiguredAuthControls() {
  const authenticated = useIsAuthenticated()
  const { instance } = useMsal()

  const [signOutError, setSignOutError] = useState(false)

  async function handleSignOut(): Promise<void> {
    setSignOutError(false)
    try {
      await signOutAndClearSession(
        instance,
        queryClient,
        instance.getActiveAccount(),
      )
    } catch {
      setSignOutError(true)
    }
  }

  const queryClient = useQueryClient()
  if (!authenticated) {
    return (
      <Button
        size="sm"
        onClick={() => void redirectForLogin(instance)}
      >
        <LogIn aria-hidden="true" />
        Sign in
      </Button>
    )
  }

  return (
    <div className="flex items-center gap-3">
      {signOutError && (
        <span role="alert" className="text-sm text-destructive">
          Sign-out could not be completed.
        </span>
      )}
      <Button size="sm" variant="outline" onClick={() => void handleSignOut()}>
        <LogOut aria-hidden="true" />
        Sign out
      </Button>
    </div>
  )
}

export function AuthControls() {
  if (isAuthenticationDisabled) {
    return <Badge variant="secondary">Authentication disabled locally</Badge>
  }

  if (!isAuthenticationConfigured) {
    return <Badge variant="outline">Authentication configuration required</Badge>
  }

  return <ConfiguredAuthControls />
}
