import { afterEach, describe, expect, it, vi } from 'vitest'

import { createApiClient } from '@/api/client'
import { ApiProblemError } from '@/api/problem-details'
import type { components } from '@/api/generated/schema'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('typed API client', () => {
  it('attaches a bearer token without logging it and keeps JSON typed', async () => {
    const token = 'mock-access-token'
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined)
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const fetchMock = vi.fn(async (_request: Request) =>
      new Response(
        JSON.stringify([{ id: 1, name: 'edge-device', client_id: null }]),
        {
          headers: { 'Content-Type': 'application/json' },
          status: 200,
        },
      ),
    )
    const client = createApiClient('http://localhost/api', async () => token, fetchMock)

    const result = await client.GET('/devices')
    const devices: components['schemas']['Device'][] | undefined = result.data

    expect(devices).toEqual([
      { id: 1, name: 'edge-device', client_id: null },
    ])
    const request = fetchMock.mock.calls[0]?.[0]
    expect(request?.headers.get('Authorization')).toBe(`Bearer ${token}`)
    expect(logSpy).not.toHaveBeenCalled()
    expect(errorSpy).not.toHaveBeenCalled()
    expect(JSON.stringify([...logSpy.mock.calls, ...errorSpy.mock.calls])).not
      .toContain(token)
  })

  it('handles a 204 response without parsing JSON', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }))
    const client = createApiClient('http://localhost/api', async () => 'token', fetchMock)

    const result = await client.DELETE('/devices/{device_id}', {
      params: { path: { device_id: 1 } },
    })

    expect(result.data).toBeUndefined()
    expect(result.error).toBeUndefined()
  })

  it('fails closed before fetch when no token is available', async () => {
    const fetchMock = vi.fn()
    const client = createApiClient('http://localhost/api', async () => null, fetchMock)

    await expect(client.GET('/devices')).rejects.toThrow(
      'An access token is required',
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('retains all RFC 7807 fields', async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          type: '/errors/device-conflict',
          title: 'Device conflict',
          status: 409,
          detail: 'The VPN client is already assigned.',
          instance: '/devices',
        }),
        {
          headers: { 'Content-Type': 'application/problem+json' },
          status: 409,
          statusText: 'Conflict',
        },
      ),
    )
    const client = createApiClient('http://localhost/api', async () => 'token', fetchMock)

    await expect(client.GET('/devices')).rejects.toMatchObject({
      name: 'ApiProblemError',
      problem: {
        type: '/errors/device-conflict',
        title: 'Device conflict',
        status: 409,
        detail: 'The VPN client is already assigned.',
        instance: '/devices',
      },
    })
  })

  it('normalizes non-JSON failures to a safe problem', async () => {
    const fetchMock = vi.fn(async () =>
      new Response('<h1>upstream details</h1>', {
        headers: { 'Content-Type': 'text/html' },
        status: 502,
        statusText: 'Bad Gateway',
      }),
    )
    const client = createApiClient('http://localhost/api', async () => 'token', fetchMock)

    try {
      await client.GET('/devices')
      expect.unreachable('The request should fail.')
    } catch (error) {
      expect(error).toBeInstanceOf(ApiProblemError)
      expect((error as ApiProblemError).problem).toMatchObject({
        type: '/errors/http-502',
        title: 'Bad Gateway',
        status: 502,
        detail: 'The server returned a non-JSON error response.',
      })
      expect((error as ApiProblemError).message).not.toContain('upstream')
    }
  })
})
