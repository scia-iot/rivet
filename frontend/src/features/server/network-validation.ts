interface ParsedNetwork {
  address: number
  prefix: number
}

const PRIVATE_RANGES = [
  [ipv4Number(10, 0, 0, 0), ipv4Number(10, 255, 255, 255)],
  [ipv4Number(172, 16, 0, 0), ipv4Number(172, 31, 255, 255)],
  [ipv4Number(192, 168, 0, 0), ipv4Number(192, 168, 255, 255)],
] as const

function ipv4Number(a: number, b: number, c: number, d: number): number {
  return a * 2 ** 24 + b * 2 ** 16 + c * 2 ** 8 + d
}

function parseNetwork(
  value: string,
  requireCidr: boolean,
): ParsedNetwork | null {
  const parts = value.split('/')
  if (parts.length > 2 || (requireCidr && parts.length !== 2)) {
    return null
  }
  const octets = parts[0]?.split('.') ?? []
  if (
    octets.length !== 4 ||
    octets.some((octet) => !/^\d{1,3}$/.test(octet))
  ) {
    return null
  }
  const numbers = octets.map(Number)
  if (numbers.some((octet) => octet < 0 || octet > 255)) {
    return null
  }

  const prefixText = parts[1]
  if (
    prefixText !== undefined &&
    (!/^\d{1,2}$/.test(prefixText) || Number(prefixText) > 32)
  ) {
    return null
  }
  return {
    address: ipv4Number(numbers[0], numbers[1], numbers[2], numbers[3]),
    prefix: prefixText === undefined ? 32 : Number(prefixText),
  }
}

function rangeFor(network: ParsedNetwork) {
  const size = 2 ** (32 - network.prefix)
  return {
    end: network.address + size - 1,
    networkAddress: network.address % size === 0,
  }
}

function isPrivateRange(start: number, end: number): boolean {
  return PRIVATE_RANGES.some(
    ([privateStart, privateEnd]) =>
      start >= privateStart && end <= privateEnd,
  )
}

export function routeNetworkError(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Enter a private IPv4 network in CIDR notation.'
  }
  const network = parseNetwork(trimmed, true)
  if (network === null) {
    return 'Enter a valid private IPv4 network in CIDR notation.'
  }
  const range = rangeFor(network)
  if (!range.networkAddress) {
    return 'Enter the network address for this CIDR block.'
  }
  if (!isPrivateRange(network.address, range.end)) {
    return 'Only private IPv4 networks can be routed.'
  }
  return null
}

export function privateNetworksError(value: string): string | null {
  if (!value.trim()) {
    return null
  }
  for (const item of value.split(',')) {
    const network = parseNetwork(item.trim(), false)
    if (network === null) {
      return 'Enter comma-separated private IPv4 addresses or CIDR networks.'
    }
    const range = rangeFor(network)
    if (!range.networkAddress) {
      return 'Enter network addresses when using CIDR notation.'
    }
    if (!isPrivateRange(network.address, range.end)) {
      return 'Only private IPv4 destinations are allowed.'
    }
  }
  return null
}
