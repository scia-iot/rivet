import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { LogIn, LogOut } from 'lucide-react'

import {
  isAuthenticationConfigured,
  isAuthenticationDisabled,
  loginRequest,
} from '@/auth/config'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

function ConfiguredAuthControls() {
  const authenticated = useIsAuthenticated()
  const { instance } = useMsal()

  if (!authenticated) {
    return (
      <Button
        size="sm"
        onClick={() => void instance.loginRedirect(loginRequest)}
      >
        <LogIn aria-hidden="true" />
        Sign in
      </Button>
    )
  }

  return (
    <Button
      size="sm"
      variant="outline"
      onClick={() => void instance.logoutRedirect()}
    >
      <LogOut aria-hidden="true" />
      Sign out
    </Button>
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
