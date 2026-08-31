export interface E2EAuthModeEnvironment {
  accessToken: string | undefined
  development: boolean
  mode: string
  requested: string | undefined
}

/**
 * Limit controlled browser identities to an explicitly selected dev server.
 */
export function allowsE2EAuthenticationMode({
  accessToken,
  development,
  mode,
  requested,
}: E2EAuthModeEnvironment): boolean {
  return (
    development &&
    mode === 'e2e' &&
    requested === 'true' &&
    Boolean(accessToken?.trim())
  )
}
