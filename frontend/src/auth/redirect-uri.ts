/**
 * Resolve the exact root redirect URI registered for the current origin.
 */
export function rootRedirectUri(origin: string): string {
  return new URL('/', origin).href
}
