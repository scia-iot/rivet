import { describe, expect, it } from 'vitest'

import { rootRedirectUri } from '@/auth/redirect-uri'

describe('root redirect URI', () => {
  it('uses the HTTPS origin root for login and logout registration', () => {
    expect(rootRedirectUri('https://control.example/deployment/path')).toBe(
      'https://control.example/',
    )
  })
})
