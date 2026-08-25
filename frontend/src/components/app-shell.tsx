import {
  KeyRound,
  Laptop,
  Network,
  ServerCog,
  ShieldCheck,
  Users,
  Workflow,
} from 'lucide-react'
import { NavLink, Outlet } from 'react-router'

import { AuthControls } from '@/auth/auth-controls'
import { routePermissions } from '@/auth/permissions'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { cn } from '@/lib/utils'

const navigation = [
  {
    to: '/',
    label: 'Overview',
    icon: Network,
    permission: routePermissions.overview,
    end: true,
  },
  {
    to: '/devices',
    label: 'Devices',
    icon: ShieldCheck,
    permission: routePermissions.devices,
  },
  {
    to: '/users',
    label: 'Users',
    icon: Users,
    permission: routePermissions.users,
  },
  {
    to: '/clients',
    label: 'VPN clients',
    icon: Laptop,
    permission: routePermissions.clients,
  },
  {
    to: '/server',
    label: 'Server',
    icon: ServerCog,
    permission: routePermissions.server,
  },
  {
    to: '/networks',
    label: 'Networks',
    icon: Workflow,
    permission: routePermissions.networks,
  },
  {
    to: '/access',
    label: 'Access',
    icon: KeyRound,
    permission: routePermissions.access,
  },
]

export function AppShell() {
  const session = usePrincipalSession()

  return (
    <div className="min-h-svh bg-muted/30">
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 lg:px-8">
          <div>
            <p className="text-lg font-semibold tracking-tight">ovpncp</p>
            <p className="text-xs text-muted-foreground">OpenVPN control panel</p>
          </div>
          <AuthControls />
        </div>
      </header>

      <div className="mx-auto grid max-w-7xl gap-6 px-4 py-6 lg:grid-cols-[14rem_1fr] lg:px-8">
        <nav aria-label="Primary navigation" className="flex gap-2 overflow-x-auto lg:flex-col">
          {navigation
            .filter(({ permission }) => hasPermission(session, permission))
            .map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  [
                    'flex shrink-0 items-center gap-2 rounded-md px-3',
                    'py-2 text-sm font-medium text-muted-foreground',
                    'hover:bg-accent hover:text-foreground',
                  ].join(' '),
                  isActive && 'bg-accent text-foreground',
                )
              }
            >
              <Icon aria-hidden="true" className="size-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <main>
          <Outlet />
        </main>
      </div>
    </div>
  )
}
