const DOMAIN_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/

const INVALID_MESSAGE = 'Enter a reachable VPN hostname or IP address.'

function validIpv6(candidate: string): boolean {
  try {
    const url = new URL(`http://[${candidate}]/`)
    const normalized = url.hostname.slice(1, -1).toLowerCase()
    return (
      url.hostname.startsWith('[') &&
      normalized !== '::' &&
      normalized !== '::1' &&
      !normalized.startsWith('fe8') &&
      !normalized.startsWith('fe9') &&
      !normalized.startsWith('fea') &&
      !normalized.startsWith('feb') &&
      !normalized.startsWith('ff')
    )
  } catch {
    return false
  }
}

export function remoteHostError(value: string): string | null {
  const candidate = value.trim()
  if (
    candidate.length === 0 ||
    candidate.length > 253 ||
    !/^[\x21-\x7E]+$/.test(candidate) ||
    candidate.includes('%')
  ) {
    return INVALID_MESSAGE
  }

  if (IPV4.test(candidate)) {
    const octets = candidate.split('.').map(Number)
    return octets.every((part) => part <= 255) &&
      octets[0] !== 0 &&
      octets[0] !== 127 &&
      octets[0] < 224 &&
      !(octets[0] === 169 && octets[1] === 254)
      ? null
      : INVALID_MESSAGE
  }

  if (candidate.includes(':')) {
    return validIpv6(candidate) ? null : INVALID_MESSAGE
  }

  const domain = candidate.endsWith('.') ? candidate.slice(0, -1) : candidate
  return domain.length > 0 &&
    domain.toLowerCase() !== 'localhost' &&
    domain.split('.').every((label) => DOMAIN_LABEL.test(label))
    ? null
    : INVALID_MESSAGE
}
