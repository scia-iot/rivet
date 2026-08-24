import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'

import { ApiProblemError } from '@/api/problem-details'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { ConfirmActionDialog } from '@/components/shared/confirm-action-dialog'
import { EmptyState } from '@/components/shared/empty-state'
import { EntitySelect } from '@/components/shared/entity-select'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Field, FieldError, FieldLabel } from '@/components/ui/field'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useClients } from '@/features/clients/client-api'
import {
  type RestrictedNetwork,
  useCloseRestrictedNetwork,
  useCreateRestrictedNetwork,
  useRestrictedNetwork,
  useRestrictedNetworks,
} from '@/features/networks/network-api'
import { privateNetworksError } from '@/features/server/network-validation'

const NETWORK_LOAD_PROBLEM = {
  type: '/errors/networks-unavailable',
  title: 'Restricted networks unavailable',
  status: 500,
  detail: [
    'Network data could not be loaded. Check the host firewall',
    'and retry.',
  ].join(' '),
}

function parseNetworkId(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) {
    return null
  }
  const networkId = Number(value)
  return Number.isSafeInteger(networkId) && networkId > 0 ? networkId : null
}

function isMissing(error: unknown): boolean {
  return error instanceof ApiProblemError && error.problem.status === 404
}

function dateLabel(value: string | null | undefined): string {
  if (!value) return 'Not ended'
  const date = new Date(value)
  if (Number.isNaN(date.valueOf())) return 'Unavailable'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
}

function NetworkStatus({ network }: { network: RestrictedNetwork }) {
  return network.end_time ? (
    <StatusBadge label="Ended" tone="neutral" />
  ) : (
    <StatusBadge label="Active" tone="positive" />
  )
}

function MissingNetwork() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Restricted network not found"
        description="The requested restricted network does not exist."
      />
      <Button asChild variant="outline">
        <Link to="/networks">Back to networks</Link>
      </Button>
    </div>
  )
}

function CreateNetworkCard({ onCancel }: { onCancel: () => void }) {
  const clients = useClients()
  const create = useCreateRestrictedNetwork()
  const navigate = useNavigate()
  const [source, setSource] = useState('')
  const [destination, setDestination] = useState('')
  const [privateNetworks, setPrivateNetworks] = useState('')
  const privateError = privateNetworksError(privateNetworks)
  const sameClient = source !== '' && source === destination
  const valid =
    source !== '' && destination !== '' && !sameClient && !privateError

  if (clients.isPending) {
    return <LoadingTable columns={2} label="Loading network form" />
  }
  if (clients.data === undefined) {
    return (
      <ProblemAlert
        onRetry={() => void clients.refetch()}
        problem={NETWORK_LOAD_PROBLEM}
      />
    )
  }
  const choices = clients.data.filter((client) => !client.revoked)

  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">Create restricted network</h2>
        <p className="text-sm text-muted-foreground">
          This change applies host firewall rules. Both clients must already
          have virtual addresses.
        </p>
      </CardHeader>
      <CardContent className="grid max-w-2xl gap-5">
        <Field>
          <FieldLabel htmlFor="network-source">Source VPN client</FieldLabel>
          <EntitySelect
            id="network-source"
            emptyText="No active VPN clients found."
            label="Source VPN client"
            onValueChange={setSource}
            options={choices.map((client) => ({
              label: client.name,
              value: client.name,
            }))}
            placeholder="Select source client"
            searchPlaceholder="Search VPN clients"
            value={source}
          />
        </Field>
        <Field data-invalid={sameClient ? true : undefined}>
          <FieldLabel htmlFor="network-destination">
            Destination VPN client
          </FieldLabel>
          <EntitySelect
            id="network-destination"
            aria-describedby={sameClient ? 'destination-error' : undefined}
            aria-invalid={sameClient ? true : undefined}
            emptyText="No other active VPN clients found."
            label="Destination VPN client"
            onValueChange={setDestination}
            options={choices
              .filter((client) => client.name !== source)
              .map((client) => ({
                label: client.name,
                value: client.name,
              }))}
            placeholder="Select destination client"
            searchPlaceholder="Search VPN clients"
            value={destination}
          />
          {sameClient ? (
            <FieldError id="destination-error">
              Choose two different VPN clients.
            </FieldError>
          ) : null}
        </Field>
        <Field data-invalid={privateError ? true : undefined}>
          <FieldLabel htmlFor="private-destinations">
            Private destinations
          </FieldLabel>
          <Textarea
            aria-describedby={privateError ? 'private-error' : undefined}
            aria-invalid={privateError ? true : undefined}
            id="private-destinations"
            onChange={(event) => setPrivateNetworks(event.target.value)}
            placeholder="192.168.60.0/24, 192.168.70.5"
            value={privateNetworks}
          />
          <p className="text-sm text-muted-foreground">
            Optional comma-separated private IPv4 addresses or CIDR networks.
          </p>
          {privateError ? (
            <FieldError id="private-error">{privateError}</FieldError>
          ) : null}
        </Field>
        <div className="flex flex-wrap justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <ConfirmActionDialog
            confirmLabel="Confirm create"
            description={
              'Apply firewall rules for these clients and optional private ' +
              'destinations. No active state is shown before confirmation.'
            }
            onConfirm={async () => {
              const created = await create.mutateAsync({
                source_name: source,
                destination_name: destination,
                private_network_addresses: privateNetworks.trim(),
              })
              if (created.id === undefined) {
                throw new Error('The created restricted network has no ID.')
              }
              toast.success('Restricted network created.')
              await navigate(`/networks/${created.id}`)
            }}
            onError={(error) => {
              if (
                error instanceof ApiProblemError &&
                error.problem.status === 412
              ) {
                toast.error('Both clients need assigned virtual addresses.')
                return
              }
              toast.error('Restricted network could not be created.')
            }}
            pendingLabel="Applying firewall…"
            title="Create restricted network?"
            trigger={
              <Button disabled={!valid} type="button">
                Create restricted network
              </Button>
            }
          />
        </div>
      </CardContent>
    </Card>
  )
}

export function NetworkListPage() {
  const networks = useRestrictedNetworks()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'server:write')
  const [creating, setCreating] = useState(false)

  return (
    <div className="space-y-6">
      <PageHeader
        title="Restricted networks"
        description="Review time-bounded firewall access between VPN clients."
        actions={
          canWrite && !creating ? (
            <Button onClick={() => setCreating(true)} type="button">
              Create network
            </Button>
          ) : undefined
        }
      />
      {creating ? (
        <CreateNetworkCard onCancel={() => setCreating(false)} />
      ) : null}
      {networks.isPending ? (
        <LoadingTable columns={6} label="Loading restricted networks" />
      ) : networks.data === undefined ? (
        <ProblemAlert
          onRetry={() => void networks.refetch()}
          problem={NETWORK_LOAD_PROBLEM}
        />
      ) : networks.data.length === 0 ? (
        <EmptyState
          title="No restricted networks"
          description="No firewall access windows have been recorded."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="Restricted networks">
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Private networks</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Ended</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {networks.data.map((network, index) => (
                <TableRow key={network.id ?? `network-${index}`}>
                  <TableCell className="font-medium">
                    {network.id === undefined ? (
                      network.source_name
                    ) : (
                      <Link
                        className="underline-offset-4 hover:underline"
                        to={`/networks/${network.id}`}
                      >
                        {network.source_name}
                      </Link>
                    )}
                  </TableCell>
                  <TableCell>{network.destination_name}</TableCell>
                  <TableCell>
                    {network.private_network_addresses || 'None'}
                  </TableCell>
                  <TableCell>{dateLabel(network.start_time)}</TableCell>
                  <TableCell>{dateLabel(network.end_time)}</TableCell>
                  <TableCell><NetworkStatus network={network} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}

function NetworkDetails({ network }: { network: RestrictedNetwork }) {
  const close = useCloseRestrictedNetwork()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'server:write')
  const items = [
    ['Source client', network.source_name],
    ['Source virtual address', network.source_virtual_address],
    ['Destination client', network.destination_name],
    ['Destination virtual address', network.destination_virtual_address],
    ['Private networks', network.private_network_addresses || 'None'],
    ['Start time', dateLabel(network.start_time)],
    ['End time', dateLabel(network.end_time)],
  ]
  return (
    <div className="space-y-6">
      <PageHeader
        title={`Restricted network ${network.id ?? ''}`.trim()}
        description="Recorded firewall access and lifecycle state."
        actions={
          <Button asChild variant="outline">
            <Link to="/networks">Back to networks</Link>
          </Button>
        }
      />
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-lg font-semibold">Network details</h2>
            <NetworkStatus network={network} />
          </div>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-5 sm:grid-cols-2">
            {items.map(([label, value]) => (
              <div key={label}>
                <dt className="text-sm text-muted-foreground">{label}</dt>
                <dd className="break-all font-medium">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      {!network.end_time && canWrite && network.id !== undefined ? (
        <Card className="border-amber-300">
          <CardHeader>
            <h2 className="text-lg font-semibold">Close restricted network</h2>
            <p className="text-sm text-muted-foreground">
              Closing removes the recorded firewall rules and cannot reopen
              this network record.
            </p>
          </CardHeader>
          <CardContent>
            <ConfirmActionDialog
              confirmLabel="Confirm close"
              description={
                'Remove this restricted network firewall policy. The network ' +
                'stays active in the UI if the host operation fails.'
              }
              onConfirm={async () => {
                await close.mutateAsync(network.id as number)
                toast.success('Restricted network closed.')
              }}
              onError={() =>
                toast.error('Restricted network could not be closed.')
              }
              pendingLabel="Removing firewall rules…"
              title="Close restricted network?"
              trigger={
                <Button type="button" variant="destructive">
                  Close network
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export function NetworkDetailPage() {
  const { networkId: networkIdParam } = useParams()
  const networkId = parseNetworkId(networkIdParam)
  const network = useRestrictedNetwork(networkId ?? 0, networkId !== null)

  if (networkId === null || isMissing(network.error)) {
    return <MissingNetwork />
  }
  if (network.isPending) {
    return <LoadingTable columns={2} label="Loading restricted network" />
  }
  if (network.data === undefined) {
    return (
      <ProblemAlert
        onRetry={() => void network.refetch()}
        problem={NETWORK_LOAD_PROBLEM}
      />
    )
  }
  return <NetworkDetails network={network.data} />
}
