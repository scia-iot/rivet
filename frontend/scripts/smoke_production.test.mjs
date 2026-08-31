import assert from 'node:assert/strict'
import test from 'node:test'

import { smokeProductionDeployment } from './smoke_production.mjs'

const securityHeaders = {
  'content-security-policy':
    "default-src 'self'; frame-ancestors 'none'",
  'cross-origin-opener-policy': 'same-origin-allow-popups',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), geolocation=(), microphone=()',
  'referrer-policy': 'no-referrer',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
}

function response(body, {
  cacheControl = 'no-store',
  contentType = 'text/html',
  status = 200,
} = {}) {
  return new Response(body, {
    status,
    headers: {
      ...securityHeaders,
      'cache-control': cacheControl,
      'content-type': contentType,
    },
  })
}

function productionFetch(requestedUrls) {
  return async (input) => {
    const url = new URL(input)
    requestedUrls.push(`${url.pathname}${url.search}`)
    if (url.pathname === '/assets/index-a1b2c3.js') {
      return response('export {}', {
        cacheControl: 'public, max-age=31536000, immutable',
        contentType: 'text/javascript',
      })
    }
    if (url.pathname === '/favicon.svg') {
      return response('<svg/>', {
        cacheControl: 'public, max-age=3600',
        contentType: 'image/svg+xml',
      })
    }
    if (url.pathname === '/api/me') {
      return response(JSON.stringify({ status: 401 }), {
        contentType: 'application/problem+json',
        status: 401,
      })
    }
    return response(
      '<html><body><div id="root"></div>' +
        '<script src="/assets/index-a1b2c3.js"></script></body></html>',
    )
  }
}

test('smokes static and protected API boundaries', async () => {
  const requestedUrls = []

  await smokeProductionDeployment(
    'https://ovpncp.example.test',
    productionFetch(requestedUrls),
  )

  assert.deepEqual(requestedUrls, [
    '/',
    '/?code=phase10-placeholder&state=phase10-placeholder',
    '/portal/devices/123',
    '/favicon.svg',
    '/assets/index-a1b2c3.js',
    '/api/me',
  ])
})

test('fails without echoing a response body or deployment URL', async () => {
  const privateBody = '/private/archive.zip?sig=sensitive'
  const fetchWithoutCsp = async () =>
    new Response(privateBody, {
      status: 200,
      headers: {
        ...securityHeaders,
        'content-security-policy': '',
        'content-type': 'text/html',
      },
    })

  await assert.rejects(
    smokeProductionDeployment(
      'https://private-control.example.test',
      fetchWithoutCsp,
    ),
    (error) => {
      assert.equal(error.message, 'Root shell is missing a required header.')
      assert.equal(error.message.includes(privateBody), false)
      assert.equal(error.message.includes('private-control'), false)
      return true
    },
  )
})
