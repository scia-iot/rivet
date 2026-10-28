import {
  expect,
  test,
  type Page,
  type Request,
  type Route,
} from '@playwright/test'

interface Device {
  client_id: number | null
  id: number
  name: string
}

interface VpnClient {
  id: number
  name: string
  revoked: boolean
}

interface User {
  display_name: string
  id: number
  issuer: string
  subject: string
}

interface AccessGrant {
  id: number
  user_id: number
  device_id: number
}

interface ApiState {
  assignedClientIds: Set<number>
  deleteDeviceRequests: number
  devices: Device[]
  grants: AccessGrant[]
  nextDeviceId: number
  nextGrantId: number
}

const clients: VpnClient[] = [
  { id: 31, name: 'laptop-alice', revoked: false },
  { id: 32, name: 'edge-spare', revoked: false },
]
const users: User[] = [
  {
    display_name: 'Alice Admin',
    id: 21,
    issuer: 'https://issuer.invalid',
    subject: 'alice',
  },
  {
    display_name: 'Bob Operator',
    id: 22,
    issuer: 'https://issuer.invalid',
    subject: 'bob',
  },
]

function newApiState(): ApiState {
  return {
    assignedClientIds: new Set(),
    deleteDeviceRequests: 0,
    devices: [
      {
        client_id: null,
        id: 11,
        name: 'Factory gateway',
      },
    ],
    grants: [],
    nextDeviceId: 12,
    nextGrantId: 1,
  }
}

function ensureAccessGrant(
  state: ApiState,
  userId: number,
  deviceId: number,
): { grant: AccessGrant; created: boolean } {
  const existing = state.grants.find((grant) =>
    grant.user_id === userId && grant.device_id === deviceId,
  )
  if (existing !== undefined) {
    return { grant: existing, created: false }
  }
  const grant = {
    id: state.nextGrantId++, user_id: userId, device_id: deviceId,
  }
  state.grants.push(grant)
  return { grant, created: true }
}

async function fulfillJson(
  route: Route,
  body: unknown,
  status = 200,
): Promise<void> {
  await route.fulfill({
    body: JSON.stringify(body),
    contentType: 'application/json',
    status,
  })
}

function requiredControlledToken(): string {
  const token = process.env.RIVET_E2E_TOKEN?.trim()
  if (!token) {
    throw new Error('The controlled E2E token is required.')
  }
  return token
}

function requireControlledToken(request: Request): void {
  expect(request.headers().authorization).toBe(
    `Bearer ${requiredControlledToken()}`,
  )
}

async function installApi(page: Page, state: ApiState): Promise<void> {
  await page.route('http://127.0.0.1:4173/api/**', async (route) => {
    const request = route.request()
    requireControlledToken(request)
    const method = request.method()
    const path = new URL(request.url()).pathname.replace(/^\/api/, '')

    if (path === '/devices' && method === 'GET') {
      await fulfillJson(route, state.devices)
      return
    }
    if (path === '/devices' && method === 'POST') {
      const requestBody = request.postDataJSON() as {
        client_id: number | null
        name: string
      }
      const created = {
        ...requestBody,
        id: state.nextDeviceId,
      }
      state.nextDeviceId += 1
      state.devices.push(created)
      await fulfillJson(route, created, 201)
      return
    }

    const deviceMatch = path.match(/^\/devices\/(\d+)$/)
    if (deviceMatch !== null) {
      const deviceId = Number(deviceMatch[1])
      const device = state.devices.find((item) => item.id === deviceId)
      if (device === undefined) {
        await fulfillJson(route, { detail: 'Device not found' }, 404)
        return
      }
      if (method === 'GET') {
        await fulfillJson(route, device)
        return
      }
      if (method === 'PATCH') {
        const update = request.postDataJSON() as {
          client_id: number | null
          name: string
        }
        Object.assign(device, update)
        await fulfillJson(route, device)
        return
      }
      if (method === 'DELETE') {
        state.deleteDeviceRequests += 1
        state.devices = state.devices.filter((item) => item.id !== deviceId)
        state.grants = state.grants.filter((grant) =>
          grant.device_id !== deviceId,
        )
        await route.fulfill({ status: 204 })
        return
      }
    }

    const deviceAccessMatch = path.match(/^\/devices\/(\d+)\/access-grants$/)
    if (deviceAccessMatch !== null) {
      const deviceId = Number(deviceAccessMatch[1])
      if (method === 'GET') {
        await fulfillJson(route, state.grants.filter((grant) =>
          grant.device_id === deviceId,
        ))
        return
      }
      if (method === 'POST') {
        const body = request.postDataJSON() as { user_ids: number[] }
        const results = [...new Set(body.user_ids)].map((userId) =>
          ensureAccessGrant(state, userId, deviceId),
        )
        const created = results.filter((result) => result.created).length
        await fulfillJson(route, {
          grants: results.map((result) => result.grant),
          created,
          already_granted: results.length - created,
        })
        return
      }
    }

    if (path === '/clients' && method === 'GET') {
      await fulfillJson(route, clients)
      return
    }
    if (path === '/users' && method === 'GET') {
      await fulfillJson(route, users)
      return
    }
    const userMatch = path.match(/^\/users\/(\d+)$/)
    if (userMatch !== null && method === 'GET') {
      await fulfillJson(route, users.find((user) =>
        user.id === Number(userMatch[1]),
      ))
      return
    }
    const userClientsMatch = path.match(/^\/users\/(\d+)\/clients$/)
    if (userClientsMatch !== null && method === 'GET') {
      await fulfillJson(
        route,
        clients.filter((client) => Number(userClientsMatch[1]) === 21 &&
          state.assignedClientIds.has(client.id)),
      )
      return
    }

    const userClientMatch = path.match(
      /^\/users\/21\/clients\/(\d+)$/,
    )
    if (userClientMatch !== null && method === 'PUT') {
      state.assignedClientIds.add(Number(userClientMatch[1]))
      await route.fulfill({ status: 204 })
      return
    }

    const userDevicesMatch = path.match(/^\/users\/(\d+)\/devices$/)
    if (userDevicesMatch !== null && method === 'GET') {
      await fulfillJson(
        route,
        state.devices.filter((device) =>
          state.grants.some((grant) =>
            grant.user_id === Number(userDevicesMatch[1]) &&
            grant.device_id === device.id,
          ),
        ),
      )
      return
    }

    const accessMatch = path.match(/^\/users\/21\/devices\/(\d+)$/)
    if (accessMatch !== null && method === 'PUT') {
      const deviceId = Number(accessMatch[1])
      const result = ensureAccessGrant(state, 21, deviceId)
      await fulfillJson(
        route,
        result.grant,
        result.created ? 201 : 200,
      )
      return
    }
    if (accessMatch !== null && method === 'DELETE') {
      state.grants = state.grants.filter((grant) =>
        grant.user_id !== 21 || grant.device_id !== Number(accessMatch[1]),
      )
      await route.fulfill({ status: 204 })
      return
    }

    throw new Error(`Unhandled E2E API request: ${method} ${path}`)
  })
}

async function useControlledRole(
  page: Page,
  role: 'device_user' | 'sysadmin',
): Promise<void> {
  await page.addInitScript((controlledRole) => {
    const browser = globalThis as unknown as {
      sessionStorage: {
        setItem: (key: string, value: string) => void
      }
    }
    browser.sessionStorage.setItem(
      'rivet:e2e:controlled-role',
      controlledRole,
    )
  }, role)
}

test('Vite proxy reaches the controlled FastAPI auth boundary', async ({
  request,
}) => {
  const unauthenticated = await request.get('/api/me')
  expect(unauthenticated.status()).toBe(401)
  expect(unauthenticated.headers()['content-type']).toContain(
    'application/problem+json',
  )

  const authenticated = await request.get('/api/me', {
    headers: {
      Authorization: `Bearer ${requiredControlledToken()}`,
    },
  })
  expect(authenticated.status()).toBe(200)
  await expect(authenticated.json()).resolves.toMatchObject({
    display_name: 'E2E administrator',
    roles: ['sysadmin'],
  })
})

test('authentication shell returns to the intended admin route', async ({
  page,
}) => {
  const state = newApiState()
  await installApi(page, state)

  await page.goto('/devices?view=all#registered')
  await expect(
    page.getByRole('heading', { name: 'Signed out' }),
  ).toBeVisible()

  await page.getByRole('button', { name: 'Sign in' }).click()

  await expect(page).toHaveURL(
    /\/devices\?view=all#registered$/,
  )
  await expect(
    page.getByRole('heading', { name: 'Devices' }),
  ).toBeVisible()
  await page.getByRole('link', { name: 'Users', exact: true }).click()
  await expect(
    page.getByRole('heading', { name: 'Users' }),
  ).toBeVisible()
})

test('admin creates, edits, and confirms device deletion', async ({ page }) => {
  const state = newApiState()
  await useControlledRole(page, 'sysadmin')
  await installApi(page, state)

  await page.goto('/devices')
  await page.getByRole('link', { name: 'Create device' }).first().click()
  await page.getByRole('textbox', { name: 'Device name' }).fill(
    'Warehouse sensor',
  )
  await page.getByRole('button', { name: 'Create device' }).click()
  await expect(
    page.getByRole('heading', { name: 'Warehouse sensor' }),
  ).toBeVisible()

  await page.getByRole('link', { name: 'Edit device' }).click()
  await page.getByRole('textbox', { name: 'Device name' }).fill(
    'Warehouse sensor 2',
  )
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(
    page.getByRole('heading', { name: 'Warehouse sensor 2' }),
  ).toBeVisible()

  await page.getByRole('button', { name: 'Delete device' }).click()
  await expect(
    page.getByRole('dialog', { name: 'Delete Warehouse sensor 2?' }),
  ).toBeVisible()
  expect(state.deleteDeviceRequests).toBe(0)

  await page
    .getByRole('dialog', { name: 'Delete Warehouse sensor 2?' })
    .getByRole('button', { name: 'Delete device' })
    .click()

  await expect(page).toHaveURL(/\/devices$/)
  await expect(
    page.getByRole('link', { name: 'Warehouse sensor 2' }),
  ).toHaveCount(0)
  expect(state.deleteDeviceRequests).toBe(1)
})

test('admin assigns a client and grants then revokes device access', async ({
  page,
}) => {
  const state = newApiState()
  await useControlledRole(page, 'sysadmin')
  await installApi(page, state)

  await page.goto('/users/21')
  await expect(
    page.getByRole('heading', { name: 'Alice Admin' }),
  ).toBeVisible()

  await page.getByRole('tab', { name: 'VPN clients' }).click()
  await page.getByRole('combobox', { name: 'VPN client' }).click()
  await page.getByRole('option', { name: /laptop-alice/ }).click()
  await page.getByRole('button', { name: 'Assign client' }).click()
  await expect(
    page.getByRole('table', { name: 'User VPN clients' }),
  ).toContainText('laptop-alice')

  await page.getByRole('tab', { name: 'Device access' }).click()
  await page.getByRole('combobox', { name: 'Device' }).click()
  await page.getByRole('option', { name: /Factory gateway/ }).click()
  await page.getByRole('button', { name: 'Grant access' }).click()
  await expect(
    page.getByRole('table', { name: 'Authorized devices' }),
  ).toContainText('Factory gateway')

  await page.getByRole('button', {
    name: 'Revoke access for Factory gateway',
  }).click()
  await expect(
    page.getByRole('dialog', {
      name: 'Revoke access to Factory gateway?',
    }),
  ).toBeVisible()
  expect(state.grants).toContainEqual({ id: 1, user_id: 21, device_id: 11 })

  await page
    .getByRole('dialog', {
      name: 'Revoke access to Factory gateway?',
    })
    .getByRole('button', { name: 'Revoke access' })
    .click()
  await expect(
    page.getByRole('heading', { name: 'No authorized devices' }),
  ).toBeVisible()
  expect(state.grants).toEqual([])
})

test('admin shares one device with multiple users in one batch', async ({
  page,
}) => {
  const state = newApiState()
  await useControlledRole(page, 'sysadmin')
  await installApi(page, state)

  await page.goto('/devices/11')
  await page.getByRole('checkbox', { name: 'Alice Admin (ID 21)' }).check()
  await page.getByRole('checkbox', { name: 'Bob Operator (ID 22)' }).check()
  await expect(page.getByText('2 of 100 users selected')).toBeVisible()

  const submitted = page.waitForRequest((request) =>
    request.method() === 'POST' &&
    new URL(request.url()).pathname === '/api/devices/11/access-grants',
  )
  await page.getByRole('button', { name: 'Grant access', exact: true }).click()
  expect((await submitted).postDataJSON()).toEqual({ user_ids: [21, 22] })
  await expect(page.getByRole('status')).toHaveText(
    '2 granted; 0 already authorized.',
  )
  await expect(page.getByRole('listitem').filter({ hasText: 'Alice Admin' }))
    .toHaveText('Alice Admin (ID 21)')
  await expect(page.getByRole('listitem').filter({ hasText: 'Bob Operator' }))
    .toHaveText('Bob Operator (ID 22)')
  await expect(page.getByRole('checkbox')).toHaveCount(0)

  for (const userId of [21, 22]) {
    await page.goto(`/users/${userId}`)
    await page.getByRole('tab', { name: 'Device access' }).click()
    await expect(page.getByRole('table', { name: 'Authorized devices' }))
      .toContainText('Factory gateway')
  }
})

test('device user cannot navigate directly to device administration', async ({
  page,
}) => {
  await useControlledRole(page, 'device_user')

  await page.goto('/devices')

  await expect(
    page.getByRole('heading', { name: 'Access forbidden' }),
  ).toBeVisible()
  await expect(
    page.getByRole('link', { name: 'Devices', exact: true }),
  ).toHaveCount(0)
  await expect(
    page.getByRole('link', { name: 'Users', exact: true }),
  ).toHaveCount(0)
  await expect(
    page.getByRole('link', { name: 'Portal', exact: true }),
  ).toBeVisible()
})
