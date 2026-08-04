import type {
  AccountInfo,
  IPublicClientApplication,
} from '@azure/msal-browser'
import type { QueryClient } from '@tanstack/react-query'

import { apiScopes, loginRequest } from '@/auth/config'

const REDIRECT_GUARD_KEY = 'ovpncp.authentication.redirect'

function claimRedirectGuard(): boolean {
  if (sessionStorage.getItem(REDIRECT_GUARD_KEY) === 'pending') {
    return false
  }
  sessionStorage.setItem(REDIRECT_GUARD_KEY, 'pending')
  return true
}

export function clearAuthenticationRedirectGuard(): void {
  sessionStorage.removeItem(REDIRECT_GUARD_KEY)
}

export async function redirectForLogin(
  instance: IPublicClientApplication,
): Promise<boolean> {
  if (!claimRedirectGuard()) {
    return false
  }

  try {
    await instance.loginRedirect({
      ...loginRequest,
      redirectStartPage: window.location.href,
    })
    return true
  } catch {
    clearAuthenticationRedirectGuard()
    throw new Error('The authentication redirect could not be started.')
  }
}

export async function redirectForInteraction(
  instance: IPublicClientApplication,
  account: AccountInfo,
): Promise<boolean> {
  if (!claimRedirectGuard()) {
    return false
  }

  try {
    await instance.acquireTokenRedirect({
      account,
      scopes: apiScopes,
      redirectStartPage: window.location.href,
    })
    return true
  } catch {
    clearAuthenticationRedirectGuard()
    throw new Error('The authentication redirect could not be started.')
  }
}

export async function signOutAndClearSession(
  instance: IPublicClientApplication,
  queryClient: QueryClient,
  account: AccountInfo | null,
): Promise<void> {
  queryClient.clear()
  instance.setActiveAccount(null)
  clearAuthenticationRedirectGuard()
  try {
    await instance.logoutRedirect({
      account: account ?? undefined,
      postLogoutRedirectUri: window.location.origin,
    })
  } catch {
    throw new Error('Sign-out could not be completed.')
  }
}
