import { describe, expect, it } from 'vitest'

import { queryKeys } from '@/api/query-keys'

describe('query key factories', () => {
  it('creates stable device collection and detail keys', () => {
    expect(queryKeys.devices.all).toEqual(['devices'])
    expect(queryKeys.devices.detail(17)).toEqual(['devices', 17])
  })

  it('creates a stable user-device authorization key', () => {
    expect(queryKeys.users.devices(7)).toEqual(['users', 7, 'devices'])
    expect(queryKeys.users.devices(7)).toEqual(queryKeys.users.devices(7))
  })

  it('creates current-user portal keys without arbitrary user IDs', () => {
    expect(queryKeys.portal.clients).toEqual(['portal', 'clients'])
    expect(queryKeys.portal.devices).toEqual(['portal', 'devices'])
    expect(queryKeys.portal.device(21)).toEqual(['portal', 'devices', 21])
  })

  it('creates stable server and restricted-network keys', () => {
    expect(queryKeys.server.routes).toEqual(['server', 'routes'])
    expect(queryKeys.networks.all).toEqual(['networks'])
    expect(queryKeys.networks.detail(4)).toEqual(['networks', 4])
  })
})
