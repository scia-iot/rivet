import { describe, expect, it } from 'vitest'

import { createQueryClient, shouldRetryRequest } from '@/app/query-client'
import { ApiProblemError } from '@/api/problem-details'

describe('query defaults', () => {
  it.each([401, 403, 404, 409, 412])(
    'does not blindly retry HTTP %s',
    (status) => {
      const error = new ApiProblemError({
        type: `/errors/http-${status}`,
        title: 'Request failed',
        status,
      })

      expect(shouldRetryRequest(0, error)).toBe(false)
    },
  )

  it('limits retries for transient and unknown failures', () => {
    expect(shouldRetryRequest(0, new Error('network failure'))).toBe(true)
    expect(shouldRetryRequest(1, new Error('network failure'))).toBe(true)
    expect(shouldRetryRequest(2, new Error('network failure'))).toBe(false)
  })

  it('configures all queries with the shared retry policy', () => {
    const client = createQueryClient()

    expect(client.getDefaultOptions().queries?.retry).toBe(shouldRetryRequest)
  })
})
