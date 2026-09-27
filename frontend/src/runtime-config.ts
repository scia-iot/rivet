/** Public deployment configuration supplied before application startup. */
interface RuntimeConfiguration {
  tenantId: string
  clientId: string
  apiScope: string
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const SCOPE_PATTERN =
  /^(api|https):\/\/[A-Za-z0-9][A-Za-z0-9.-]*\/[A-Za-z0-9._~/-]+$/

function validateRuntimeConfiguration(value: unknown): RuntimeConfiguration | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  const config = value as Record<string, unknown>
  if (
    Object.keys(config).length !== 3 ||
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
    tenantId: config.tenantId,
    clientId: config.clientId,
    apiScope: config.apiScope,
  }
}

// Presence is authoritative even when the payload is malformed. Container builds
// additionally require runtime configuration when the script fails to load.
export const usesRuntimeConfiguration =
  import.meta.env.VITE_RUNTIME_CONFIG === 'true' ||
  Object.prototype.hasOwnProperty.call(window, '__OVPNCP_CONFIG__')

export const runtimeConfiguration = validateRuntimeConfiguration(
  window.__OVPNCP_CONFIG__,
)
