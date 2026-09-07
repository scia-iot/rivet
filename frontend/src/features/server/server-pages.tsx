import { useState } from 'react'
import { Link } from 'react-router'
import { toast } from 'sonner'

import { ApiProblemError } from '@/api/problem-details'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { ConfirmActionDialog } from '@/components/shared/confirm-action-dialog'
import { EmptyState } from '@/components/shared/empty-state'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Field, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { routeNetworkError } from '@/features/server/network-validation'
import {
  type ServiceHealth,
  type ServerConfiguration,
  useAddServerRoute,
  useAssignableVirtualAddresses,
  useDeleteServerRoute,
  useInitializeServer,
  useServer,
  useServerHealth,
  useServerRoutes,
} from '@/features/server/server-api'

const SERVER_LOAD_PROBLEM = {
  type: '/errors/server-unavailable',
  title: 'Server data unavailable',
  status: 500,
  detail: 'Server data could not be loaded. Check the host service and retry.',
}
const ROUTE_LOAD_PROBLEM = {
  type: '/errors/routes-unavailable',
  title: 'Server routes unavailable',
  status: 500,
  detail: 'Routes could not be loaded. Check the host route service and retry.',
}
const HEALTH_REFRESH_PROBLEM = {
  type: '/errors/health-refresh-failed',
  title: 'OpenVPN health refresh failed',
  status: 500,
  detail:
    'The last health report may be stale. Check the host service and retry.',
}

function isMissingServer(error: unknown): boolean {
  return error instanceof ApiProblemError && error.problem.status === 404
}

function healthTone(status: string) {
  const normalized = status.toLowerCase()
  if (normalized.includes('failed') || normalized.includes('inactive')) {
    return 'negative' as const
  }
  if (normalized.includes('active') || normalized.includes('running')) {
    return 'positive' as const
  }
  return 'warning' as const
}

function HealthSummary({ health }: { health: ServiceHealth }) {
  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">OpenVPN health</h2>
        <p className="text-sm text-muted-foreground">
          Refreshes every 15 seconds while this page is visible.
        </p>
      </CardHeader>
      <CardContent className="flex flex-wrap items-center gap-3">
        <StatusBadge label={health.status} tone={healthTone(health.status)} />
        {health.time ? (
          <span className="text-sm">Since {health.time}</span>
        ) : null}
        {health.period ? (
          <span className="text-sm text-muted-foreground">
            Reported period: {health.period}
          </span>
        ) : null}
      </CardContent>
    </Card>
  )
}

function ServerConfigurationSummary({
  server,
}: {
  server: ServerConfiguration
}) {
  const items = [
    ['Protocol', server.proto.toUpperCase()],
    ['Port', server.port],
    ['Device', server.dev],
    ['Topology', server.topology],
    [
      'VPN network',
      `${server.network_address} / ${server.subnet_mask}`,
    ],
    ['Exclusive client config', server.ccd_exclusive ? 'Enabled' : 'Disabled'],
  ]
  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">Configuration summary</h2>
        <p className="text-sm text-muted-foreground">
          Security-sensitive certificate and key paths are intentionally hidden.
        </p>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {items.map(([label, value]) => (
            <div key={label}>
              <dt className="text-sm text-muted-foreground">{label}</dt>
              <dd className="font-medium">{value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  )
}

function VirtualAddressSummary({
  addresses,
  total,
}: {
  addresses: ReadonlyArray<{ ip: string }>
  total: number
}) {
  const available = addresses.length
  const assigned = Math.max(total - available, 0)
  const summary = [
    ['Total', total],
    ['Assigned', assigned],
    ['Available', available],
  ] as const

  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">Virtual addresses</h2>
        <p className="text-sm text-muted-foreground">
          Current allocation across the configured address pool.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <dl
          aria-label="Virtual address summary"
          className="grid grid-cols-3 gap-3"
        >
          {summary.map(([label, value]) => (
            <div className="rounded-md border p-4" key={label}>
              <dt className="text-sm text-muted-foreground">{label}</dt>
              <dd className="text-2xl font-semibold">{value}</dd>
            </div>
          ))}
        </dl>
        {available === 0 ? (
          <EmptyState
            title="No assignable virtual addresses"
            description="Every address is assigned or the pool is empty."
          />
        ) : (
          <div className="space-y-2">
            <h3 className="text-sm font-medium">
              Assignable virtual addresses
            </h3>
            <p
              aria-label="Assignable virtual addresses"
              className="break-words text-sm"
            >
              {addresses.map((address) => address.ip).join(', ')}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function ServerPage() {
  const health = useServerHealth()
  const server = useServer()
  const addresses = useAssignableVirtualAddresses()
  const initialize = useInitializeServer()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'server:write')
  const missing = isMissingServer(server.error)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Server"
        description={[
          'Review OpenVPN health, configuration, and address',
          'capacity.',
        ].join(' ')}
        actions={
          <Button asChild variant="outline">
            <Link to="/server/routes">Manage routes</Link>
          </Button>
        }
      />
      {health.isPending ? (
        <Card>
          <CardContent className="pt-6" role="status">
            Loading OpenVPN health…
          </CardContent>
        </Card>
      ) : health.data === undefined ? (
        <ProblemAlert
          onRetry={() => void health.refetch()}
          problem={SERVER_LOAD_PROBLEM}
        />
      ) : (
        <>
          <HealthSummary health={health.data} />
          {health.isError ? (
            <ProblemAlert
              onRetry={() => void health.refetch()}
              problem={HEALTH_REFRESH_PROBLEM}
              stale
            />
          ) : null}
        </>
      )}
      {missing ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Server not initialized</h2>
            <p className="text-sm text-muted-foreground">
              Initialize from the reviewed host OpenVPN configuration before
              managing routes or virtual addresses.
            </p>
          </CardHeader>
          {canWrite ? (
            <CardContent>
              <ConfirmActionDialog
                confirmLabel="Confirm initialize"
                description={
                  'Read the host OpenVPN configuration and create the server ' +
                  'address pool. Wait for backend confirmation before use.'
                }
                onConfirm={async () => {
                  await initialize.mutateAsync()
                  toast.success('Server initialized.')
                }}
                onError={() => toast.error('Server could not be initialized.')}
                pendingLabel="Initializing…"
                title="Initialize server?"
                trigger={<Button type="button">Initialize server</Button>}
              />
            </CardContent>
          ) : null}
        </Card>
      ) : server.isPending || addresses.isPending ? (
        <LoadingTable columns={2} label="Loading server configuration" />
      ) : server.data === undefined || addresses.data === undefined ? (
        <ProblemAlert
          onRetry={() => {
            void server.refetch()
            void addresses.refetch()
          }}
          problem={SERVER_LOAD_PROBLEM}
        />
      ) : (
        <>
          <ServerConfigurationSummary server={server.data} />
          <VirtualAddressSummary
            addresses={addresses.data}
            total={server.data.virtual_addresses.length}
          />
        </>
      )}
    </div>
  )
}

export function ServerRoutesPage() {
  const routes = useServerRoutes()
  const addRoute = useAddServerRoute()
  const deleteRoute = useDeleteServerRoute()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'server:write')
  const [network, setNetwork] = useState('')
  const validationError = network ? routeNetworkError(network) : null

  return (
    <div className="space-y-6">
      <PageHeader
        title="Server routes"
        description="Manage private routes on the OpenVPN host."
        actions={
          <Button asChild variant="outline">
            <Link to="/server">Back to server</Link>
          </Button>
        }
      />
      {canWrite ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Add private route</h2>
            <p className="text-sm text-muted-foreground">
              Route changes affect the host and require explicit confirmation.
            </p>
          </CardHeader>
          <CardContent
            className={[
              'flex max-w-2xl flex-col gap-3 sm:flex-row',
              'sm:items-end',
            ].join(' ')}
          >
            <Field data-invalid={validationError ? true : undefined}>
              <FieldLabel htmlFor="route-network">Private network</FieldLabel>
              <Input
                aria-describedby={validationError ? 'route-error' : undefined}
                aria-invalid={validationError ? true : undefined}
                id="route-network"
                onChange={(event) => setNetwork(event.target.value)}
                placeholder="192.168.40.0/24"
                value={network}
              />
              {validationError ? (
                <FieldError id="route-error">{validationError}</FieldError>
              ) : null}
            </Field>
            <ConfirmActionDialog
              confirmLabel="Confirm add"
              description={
                'Add this private route to the OpenVPN host. The route is ' +
                'shown only after the backend confirms the host change.'
              }
              onConfirm={async () => {
                await addRoute.mutateAsync(network.trim())
                setNetwork('')
                toast.success('Server route added.')
              }}
              onError={() => toast.error('Server route could not be added.')}
              pendingLabel="Adding route…"
              title="Add server route?"
              trigger={
                <Button
                  disabled={routeNetworkError(network) !== null}
                  type="button"
                >
                  Add route
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : null}
      {routes.isPending ? (
        <LoadingTable columns={2} label="Loading server routes" />
      ) : routes.data === undefined ? (
        <ProblemAlert
          onRetry={() => void routes.refetch()}
          problem={ROUTE_LOAD_PROBLEM}
        />
      ) : routes.data.length === 0 ? (
        <EmptyState
          title="No server routes"
          description="No private routes are configured on the VPN device."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="Server routes">
            <TableHeader>
              <TableRow>
                <TableHead>Route</TableHead>
                <TableHead>Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {routes.data.map((route) => {
                const routeNetwork = route.split(/\s+/, 1)[0] ?? route
                return (
                  <TableRow key={route}>
                    <TableCell className="font-medium">{route}</TableCell>
                    <TableCell>
                      {canWrite ? (
                        <ConfirmActionDialog
                          confirmLabel="Confirm remove"
                          description={
                            'Remove this route from the OpenVPN host. The ' +
                            'current route remains visible if the host fails.'
                          }
                          onConfirm={async () => {
                            await deleteRoute.mutateAsync(routeNetwork)
                            toast.success('Server route removed.')
                          }}
                          onError={() =>
                            toast.error('Server route could not be removed.')
                          }
                          pendingLabel="Removing route…"
                          title="Remove server route?"
                          trigger={
                            <Button type="button" variant="outline">
                              Remove
                            </Button>
                          }
                        />
                      ) : null}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
