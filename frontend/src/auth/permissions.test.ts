import { describe, expect, it } from 'vitest'

import {
  PERMISSIONS,
  permissionDescriptions,
  roleDescriptions,
  routePermissions,
} from '@/auth/permissions'

describe('authorization metadata', () => {
  it('keeps one authoritative frontend permission vocabulary', () => {
    expect(PERMISSIONS).toEqual([
      'devices:read',
      'devices:write',
      'users:read',
      'users:write',
      'clients:read',
      'clients:write',
      'access:read',
      'access:grant',
      'server:read',
      'server:write',
    ])
    expect(Object.keys(permissionDescriptions)).toEqual(PERMISSIONS)
  })

  it('describes every canonical backend role', () => {
    expect(Object.keys(roleDescriptions)).toEqual([
      'sysadmin',
      'device_user',
      'service_admin',
    ])
  })

  it('declares required permissions for every administration route', () => {
    expect(routePermissions).toEqual({
      overview: 'server:read',
      devices: 'devices:read',
      createDevice: 'devices:write',
      deviceDetail: 'devices:read',
      editDevice: 'devices:write',
      users: 'users:read',
      createUser: 'users:write',
      userDetail: 'users:read',
      editUser: 'users:write',
      clients: 'clients:read',
      clientDetail: 'clients:read',
      server: 'server:read',
      serverRoutes: 'server:read',
      networks: 'server:read',
      networkDetail: 'server:read',
      access: 'access:read',
    })
  })
})
