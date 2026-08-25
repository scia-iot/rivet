export const PERMISSIONS = [
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
] as const

export type Permission = (typeof PERMISSIONS)[number]

export const permissionDescriptions = {
  'devices:read': 'View registered devices.',
  'devices:write': 'Create, change, and delete devices.',
  'users:read': 'View registered users and their client assignments.',
  'users:write': 'Create, change, and delete users and client assignments.',
  'clients:read': 'View VPN clients and certificate status.',
  'clients:write': 'Manage VPN clients, certificates, and addresses.',
  'access:read': 'View application device-access grants.',
  'access:grant': 'Grant and revoke application device access.',
  'server:read': 'View server, route, and restricted-network state.',
  'server:write': 'Change server, route, and restricted-network state.',
} satisfies Record<Permission, string>

export const roleDescriptions: Record<string, string> = {
  sysadmin: 'System administrator with control-plane management permissions.',
  device_user: 'Device user limited to explicitly owned and granted resources.',
}

export const routePermissions = {
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
} as const satisfies Record<string, Permission>
