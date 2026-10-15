import {
  type EntraRuntimeConfiguration,
  validateEntraRuntimeConfiguration,
} from '@/auth/entra-runtime-configuration'

/** Dispatch public configuration only to a supported browser provider. */
function validateRuntimeConfiguration(value: unknown): EntraRuntimeConfiguration | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null
  }
  const config = value as Record<string, unknown>
  const count = Object.keys(config).length
  if (
    (count !== 3 && count !== 4) ||
    (count === 4 && config.provider !== 'entra') ||
    (count === 3 && Object.prototype.hasOwnProperty.call(config, 'provider'))
  ) {
    return null
  }
  return validateEntraRuntimeConfiguration(config)
}

// Presence is authoritative even when the payload is malformed. Container builds
// additionally require runtime configuration when the script fails to load.
export const usesRuntimeConfiguration =
  import.meta.env.VITE_RUNTIME_CONFIG === 'true' ||
  Object.prototype.hasOwnProperty.call(window, '__RIVET_CONFIG__')

export const runtimeConfiguration = validateRuntimeConfiguration(
  window.__RIVET_CONFIG__,
)
