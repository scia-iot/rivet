export const queryKeys = {
  currentPrincipal: {
    detail: ['current-principal'] as const,
  },
  clients: {
    all: ['clients'] as const,
    detail: (name: string) => ['clients', name] as const,
  },
  devices: {
    all: ['devices'] as const,
    detail: (id: number) => ['devices', id] as const,
  },
  networks: {
    all: ['networks'] as const,
    detail: (id: number) => ['networks', id] as const,
  },
  server: {
    all: ['server'] as const,
    health: ['server', 'health'] as const,
  },
  users: {
    all: ['users'] as const,
    detail: (id: number) => ['users', id] as const,
  },
}
