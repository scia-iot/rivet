import { describe, expect, it } from 'vitest'

import {
  privateNetworksError,
  routeNetworkError,
} from '@/features/server/network-validation'

describe('privileged network input validation', () => {
  it.each([
    '192.168.20.0/24',
    '10.20.0.0/16',
    '172.16.4.4/32',
  ])('accepts private IPv4 route %s', (network) => {
    expect(routeNetworkError(network)).toBeNull()
  })

  it.each([
    ['', 'Enter a private IPv4 network in CIDR notation.'],
    ['not-a-route', 'Enter a valid private IPv4 network in CIDR notation.'],
    ['8.8.8.0/24', 'Only private IPv4 networks can be routed.'],
    ['192.168.20.3/24', 'Enter the network address for this CIDR block.'],
  ])('rejects invalid route %s', (network, error) => {
    expect(routeNetworkError(network)).toBe(error)
  })

  it('validates every optional private destination without echoing it', () => {
    expect(privateNetworksError('192.168.1.1, 10.2.0.0/16')).toBeNull()
    expect(privateNetworksError('')).toBeNull()
    expect(privateNetworksError('192.168.1.1; unsafe')).toBe(
      'Enter comma-separated private IPv4 addresses or CIDR networks.',
    )
    expect(privateNetworksError('8.8.8.8')).toBe(
      'Only private IPv4 destinations are allowed.',
    )
  })
})
