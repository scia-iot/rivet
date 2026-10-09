import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { chromium, expect } from '@playwright/test'

/** Verify one compiled image accepts different runtime settings and fails closed. */
export async function checkContainerBrowser(directory) {
  const browser = await chromium.launch()
  const origin = 'http://localhost:4189'
  const first = {
    tenantId: '11111111-1111-1111-1111-111111111111',
    clientId: '22222222-2222-2222-2222-222222222222',
    apiScope: 'api://first-api/access',
  }
  const second = {
    tenantId: '33333333-3333-3333-3333-333333333333',
    clientId: '44444444-4444-4444-4444-444444444444',
    apiScope: 'api://second-api/access',
  }
  try {
    for (const configuration of [undefined, {}, first, second]) {
      const context = await browser.newContext()
      const page = await context.newPage()
      let authorizationUrl
      await page.route('**/*', async (route) => {
        const url = new URL(route.request().url())
        if (url.origin === origin) {
          if (url.pathname === '/runtime-config.js') {
            await route.fulfill({
              status: configuration === undefined ? 404 : 200,
              contentType: 'text/javascript',
              body: configuration === undefined ? '' :
                `window.__RIVET_CONFIG__=${JSON.stringify(configuration)};`,
            })
            return
          }
          const path = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
          const contentType = path.endsWith('.js') ? 'text/javascript' :
            path.endsWith('.css') ? 'text/css' : 'text/html'
          await route.fulfill({ contentType, body: readFileSync(join(directory, path)) })
          return
        }
        if (url.pathname.endsWith('/.well-known/openid-configuration')) {
          const authority = `https://login.microsoftonline.com/${configuration.tenantId}`
          await route.fulfill({ json: {
            authorization_endpoint: `${authority}/oauth2/v2.0/authorize`,
            token_endpoint: `${authority}/oauth2/v2.0/token`,
            end_session_endpoint: `${authority}/oauth2/v2.0/logout`,
            issuer: `${authority}/v2.0`,
          } })
          return
        }
        if (url.pathname.endsWith('/oauth2/v2.0/authorize')) {
          authorizationUrl = url
          await route.fulfill({ contentType: 'text/html', body: 'Mock sign-in' })
          return
        }
        await route.abort()
      })
      await page.goto(origin)
      if (configuration === undefined || !configuration.tenantId) {
        await expect(page.getByRole('alert')).toContainText(
          'Authentication configuration required',
        )
        await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toHaveCount(0)
      } else {
        await page.getByRole('button', { name: 'Sign in', exact: true }).click()
        await expect.poll(() => authorizationUrl !== undefined).toBe(true)
        assert.equal(authorizationUrl.pathname,
          `/${configuration.tenantId}/oauth2/v2.0/authorize`)
        assert.equal(authorizationUrl.searchParams.get('client_id'), configuration.clientId)
        assert.ok(authorizationUrl.searchParams.get('scope').split(' ').includes(configuration.apiScope))
      }
      await context.close()
    }
    process.stdout.write('Container browser checks passed for missing, invalid, and two runtime configurations.\n')
  } finally {
    await browser.close()
  }
}
