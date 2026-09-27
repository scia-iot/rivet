import createClient, {
  type Client,
  type Middleware,
} from 'openapi-fetch'

import { usesRuntimeConfiguration } from '@/runtime-config'

import type { paths } from '@/api/generated/schema'
import {
  ApiProblemError,
  normalizeApiProblem,
} from '@/api/problem-details'

export type AccessTokenProvider = () => Promise<string | null>

export function createApiClient(
  baseUrl: string,
  getAccessToken: AccessTokenProvider,
  fetchImplementation: (request: Request) => Promise<Response> = globalThis.fetch,
): Client<paths> {
  const client = createClient<paths>({
    baseUrl,
    fetch: fetchImplementation,
  })

  const authentication: Middleware = {
    async onRequest({ request }) {
      const token = await getAccessToken()
      if (!token) {
        throw new Error('An access token is required for API requests.')
      }

      request.headers.set('Authorization', `Bearer ${token}`)
      return request
    },
  }
  const problemResponses: Middleware = {
    async onResponse({ request, response }) {
      if (!response.ok) {
        throw new ApiProblemError(
          await normalizeApiProblem(response, request.url),
        )
      }

      return response
    },
  }

  client.use(authentication, problemResponses)
  return client
}

export const apiBaseUrl = (
  usesRuntimeConfiguration ? '/api' : import.meta.env.VITE_API_BASE_URL ?? '/api'
).replace(/\/$/, '')
