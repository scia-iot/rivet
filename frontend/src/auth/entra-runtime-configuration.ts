/** Public, validated Entra settings for the selected browser provider. */
export interface EntraRuntimeConfiguration {
  provider: 'entra'
  tenantId: string
  clientId: string
  apiScope: string
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const SCOPE_PATTERN =
  /^(api|https):\/\/[A-Za-z0-9][A-Za-z0-9.-]*\/[A-Za-z0-9._~/-]+$/

export function validateEntraRuntimeConfiguration(
  config: Record<string, unknown>,
): EntraRuntimeConfiguration | null {
  if (
    typeof config.tenantId !== 'string' ||
    typeof config.clientId !== 'string' ||
    typeof config.apiScope !== 'string' ||
    config.tenantId.length !== 36 ||
    config.clientId.length !== 36 ||
    /\s/.test(config.apiScope) ||
    !UUID_PATTERN.test(config.tenantId) ||
    !UUID_PATTERN.test(config.clientId) ||
    config.apiScope.length > 2048 ||
    !SCOPE_PATTERN.test(config.apiScope)
  ) {
    return null
  }
  return {
    provider: 'entra',
    tenantId: config.tenantId,
    clientId: config.clientId,
    apiScope: config.apiScope,
  }
}
