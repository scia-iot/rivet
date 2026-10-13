import { describe, expect, it } from 'vitest'

import { remoteHostError } from './remote-host-validation'

describe('remoteHostError', () => {
  it.each([
    'vpn.example.test',
    '10.20.30.40',
    '2001:db8::1',
  ])('accepts a reachable hostname or IP: %s', (value) => {
    expect(remoteHostError(value)).toBeNull()
  })

  it.each([
    '::::',
    '2001:::1',
    '::1',
    'fe80::1',
    '127.0.0.1',
    '169.254.1.2',
    '0.0.0.0',
    '224.0.0.1',
    'localhost',
    'vpn host.example',
  ])('rejects an invalid or local-only endpoint: %s', (value) => {
    expect(remoteHostError(value)).toBe(
      'Enter a reachable VPN hostname or IP address.',
    )
  })
})
