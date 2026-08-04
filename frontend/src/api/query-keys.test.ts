import { describe, expect, it } from 'vitest'

import { queryKeys } from '@/api/query-keys'

describe('query key factories', () => {
  it('creates stable device collection and detail keys', () => {
    expect(queryKeys.devices.all).toEqual(['devices'])
    expect(queryKeys.devices.detail(17)).toEqual(['devices', 17])
  })
})
