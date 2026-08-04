import { QueryClient } from '@tanstack/react-query'

import { ApiProblemError } from '@/api/problem-details'

const NON_RETRYABLE_STATUSES = new Set([401, 403, 404, 409, 412])
const MAX_TRANSIENT_RETRIES = 2

export function shouldRetryRequest(
  failureCount: number,
  error: unknown,
): boolean {
  if (
    error instanceof ApiProblemError &&
    NON_RETRYABLE_STATUSES.has(error.problem.status)
  ) {
    return false
  }

  return failureCount < MAX_TRANSIENT_RETRIES
}

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      mutations: {
        retry: false,
      },
      queries: {
        refetchOnWindowFocus: false,
        retry: shouldRetryRequest,
        staleTime: 30_000,
      },
    },
  })
}
