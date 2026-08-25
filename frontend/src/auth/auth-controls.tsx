import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { useQueryClient } from '@tanstack/react-query'
import { LogIn, LogOut, UserRound } from 'lucide-react'
import { useState } from 'react'

import {
  isAuthenticationConfigured,
  isAuthenticationDisabled,
} from '@/auth/config'
import {
  PERMISSIONS,
  type Permission,
  permissionDescriptions,
  roleDescriptions,
} from '@/auth/permissions'
import {
  redirectForLogin,
  signOutAndClearSession,
} from '@/auth/redirect-coordinator'
import { usePrincipalSession } from '@/auth/use-principal-session'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

function isPermission(value: string): value is Permission {
  return (PERMISSIONS as readonly string[]).includes(value)
}

function roleLabel(role: string): string {
  if (role === 'sysadmin') {
    return 'System administrator'
  }
  if (role === 'device_user') {
    return 'Device user'
  }
  return 'Application role'
}

function AccountAccessMenu() {
  const { principal } = usePrincipalSession()
  if (principal === null) {
    return null
  }

  const roles = principal.roles.map((role) => ({
    description:
      roleDescriptions[role] ?? 'This role has no management capabilities.',
    label: roleLabel(role),
  }))
  const permissions = principal.permissions.filter(isPermission)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          aria-label={`Account access for ${principal.display_name}`}
          size="sm"
          variant="ghost"
        >
          <UserRound aria-hidden="true" />
          Access
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        aria-label="Account roles and permissions"
        className="w-80 p-3"
      >
        <p className="font-medium">{principal.display_name}</p>
        <section className="mt-3" aria-labelledby="account-roles-heading">
          <h2
            className="text-xs font-semibold uppercase text-muted-foreground"
            id="account-roles-heading"
          >
            Roles
          </h2>
          <ul className="mt-1 space-y-2">
            {roles.map((role) => (
              <li key={role.label}>
                <p className="text-sm font-medium">{role.label}</p>
                <p className="text-xs text-muted-foreground">
                  {role.description}
                </p>
              </li>
            ))}
          </ul>
        </section>
        <section className="mt-3" aria-labelledby="account-permissions-heading">
          <h2
            className="text-xs font-semibold uppercase text-muted-foreground"
            id="account-permissions-heading"
          >
            Permissions
          </h2>
          {permissions.length === 0 ? (
            <p className="mt-1 text-xs text-muted-foreground">
              No control-plane management permissions.
            </p>
          ) : (
            <ul className="mt-1 space-y-2">
              {permissions.map((permission) => (
                <li key={permission}>
                  <p className="font-mono text-xs">{permission}</p>
                  <p className="text-xs text-muted-foreground">
                    {permissionDescriptions[permission]}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

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
      <Button size="sm" onClick={() => void redirectForLogin(instance)}>
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
      <AccountAccessMenu />
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
