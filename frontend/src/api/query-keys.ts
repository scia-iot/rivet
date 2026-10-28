export const queryKeys = {
  currentPrincipal: {
    detail: ['current-principal'] as const,
  },
  clients: {
    all: ['clients'] as const,
    detail: (name: string) => ['clients', name] as const,
    addresses: ['clients', 'addresses', 'assignable'] as const,
  },
  devices: {
    all: ['devices'] as const,
    detail: (id: number) => ['devices', id] as const,
  },
  networks: {
    all: ['networks'] as const,
    detail: (id: number) => ['networks', id] as const,
  },
  portal: {
    all: ['portal'] as const,
    clients: ['portal', 'clients'] as const,
    devices: ['portal', 'devices'] as const,
    networks: ['portal', 'networks'] as const,
    network: (id: number) => ['portal', 'networks', id] as const,
    device: (id: number) => ['portal', 'devices', id] as const,
  },
  server: {
    all: ['server'] as const,
    health: ['server', 'health'] as const,
    routes: ['server', 'routes'] as const,
  },
  users: {
    all: ['users'] as const,
    detail: (id: number) => ['users', id] as const,
    clients: (id: number) => ['users', id, 'clients'] as const,
    clientOwnership: ['users', 'client-ownership'] as const,
    clientOwnershipFor: (userIds: number[]) =>
      ['users', 'client-ownership', ...userIds] as const,
    devices: (id: number) => ['users', id, 'devices'] as const,
  },
}
