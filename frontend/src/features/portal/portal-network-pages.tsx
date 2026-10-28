import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'

import { ApiProblemError } from '@/api/problem-details'
import { ConfirmActionDialog } from '@/components/shared/confirm-action-dialog'
import { EmptyState } from '@/components/shared/empty-state'
import { EntitySelect } from '@/components/shared/entity-select'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Field, FieldLabel } from '@/components/ui/field'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  type PortalNetwork,
  useClosePortalNetwork,
  useCreatePortalNetwork,
  usePortalClients,
  usePortalDevices,
  usePortalNetwork,
  usePortalNetworks,
} from '@/features/portal/portal-api'

const NETWORKS_PROBLEM = {
  type: '/errors/portal-networks-unavailable',
  title: 'Networks unavailable',
  status: 500,
  detail: 'Your networks could not be loaded. Try again.',
}
const CREATE_DESCRIPTION = [
  'Allow direct VPN traffic between your selected client and the granted',
  'device until this network is closed. This does not confirm live connectivity.',
].join(' ')

function dateLabel(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : '—'
}

function NetworkStatus({ network }: { network: PortalNetwork }) {
  return (
    <StatusBadge
      label={network.end_time ? 'Closed' : 'Active'}
      tone={network.end_time ? 'neutral' : 'positive'}
    />
  )
}

function createError(error: unknown): string {
  if (error instanceof ApiProblemError) {
    if (error.problem.status === 403) {
      return [
        'Access changed. Refresh your owned clients and granted devices',
        'before trying again.',
      ].join(' ')
    }
    if (error.problem.status === 412) {
      return [
        'Both clients need assigned VPN addresses. Ask an administrator',
        'to complete provisioning.',
      ].join(' ')
    }
    if (error.problem.status === 409) {
      return [
        'Check that both clients have active credentials and ask an',
        'administrator to check pending VPN operations.',
      ].join(' ')
    }
  }
  return [
    'Network creation could not be confirmed. Retry the same request or ask',
    'an administrator to check pending VPN operations.',
  ].join(' ')
}

function CreatePortalNetwork({ onCancel }: { onCancel: () => void }) {
  const clients = usePortalClients()
  const devices = usePortalDevices()
  const create = useCreatePortalNetwork()
  const navigate = useNavigate()
  const [source, setSource] = useState('')
  const [destination, setDestination] = useState('')
  const [failure, setFailure] = useState('')
  const valid =
    clients.data?.some((client) => client.name === source && !client.revoked) &&
    devices.data?.some(
      (device) => String(device.id) === destination && device.client_id !== null,
    )
  const loading = clients.isPending || devices.isPending
  const failed = clients.data === undefined || devices.data === undefined

  return (
    <Card>
      <CardHeader>
        <CardTitle>Create restricted network</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Choose an owned VPN client and a granted device. Both need active
          credentials and assigned VPN addresses. Access covers both directions,
          all ports and protocols, until closed.
        </p>
        {loading ? (
          <p role="status">Loading your clients and devices…</p>
        ) : failed ? (
          <ProblemAlert
            problem={{
              ...NETWORKS_PROBLEM,
              detail: 'Your clients or devices could not be loaded.',
            }}
            onRetry={() => {
              void clients.refetch()
              void devices.refetch()
            }}
          />
        ) : (
          <>
            {!clients.data?.some((client) => !client.revoked) ? (
              <p>
                Ask an administrator to assign an active VPN client to your
                account.
              </p>
            ) : null}
            {devices.data?.length === 0 ? (
              <p>
                No devices granted. Ask an administrator to grant access to a
                device.
              </p>
            ) : null}
            <Field>
              <FieldLabel htmlFor="portal-source">Source VPN client</FieldLabel>
              <EntitySelect
                id="portal-source"
                label="Source VPN client"
                value={source}
                onValueChange={(value) => {
                  setSource(value)
                  setFailure('')
                }}
                options={(clients.data ?? []).map((client) => ({
                  value: client.name,
                  label: client.revoked
                    ? `${client.name} (revoked)`
                    : client.name,
                  disabled: client.revoked,
                }))}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="portal-destination">
                Destination device
              </FieldLabel>
              <EntitySelect
                id="portal-destination"
                label="Destination device"
                value={destination}
                onValueChange={(value) => {
                  setDestination(value)
                  setFailure('')
                }}
                options={(devices.data ?? [])
                  .filter((device) => device.id !== null)
                  .map((device) => ({
                    value: String(device.id),
                    label: device.client_id === null
                      ? `${device.name} (VPN client not assigned)`
                      : device.name,
                    disabled: device.client_id === null,
                  }))}
              />
            </Field>
          </>
        )}
        <div className="flex gap-3">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <ConfirmActionDialog
            title="Create restricted network?"
            description={failure || CREATE_DESCRIPTION}
            confirmLabel="Confirm create"
            pendingLabel="Applying firewall…"
            trigger={
              <Button type="button" disabled={!valid || loading || failed}>
                Create restricted network
              </Button>
            }
            onConfirm={async () => {
              setFailure('')
              const network = await create.mutateAsync({
                source_name: source,
                destination_device_id: Number(destination),
              })
              if (network.id === undefined) {
                throw new Error('The created network has no ID.')
              }
              toast.success('Restricted network created.')
              await navigate(`/portal/networks/${network.id}`)
            }}
            onError={(error) => setFailure(createError(error))}
          />
        </div>
      </CardContent>
    </Card>
  )
}

export function PortalNetworksPage() {
  const networks = usePortalNetworks()
  const [creating, setCreating] = useState(false)

  return (
    <div className="space-y-6">
      <PageHeader
        title="My networks"
        description={
          'Access and history for VPN clients you currently own. Device grants ' +
          'permit creation; removing a grant does not close existing networks.'
        }
        actions={!creating ? (
          <Button type="button" onClick={() => setCreating(true)}>
            Create network
          </Button>
        ) : undefined}
      />
      {creating ? (
        <CreatePortalNetwork onCancel={() => setCreating(false)} />
      ) : null}
      {networks.isPending ? (
        <LoadingTable columns={5} label="Loading my networks" />
      ) : networks.data === undefined ? (
        <ProblemAlert
          problem={NETWORKS_PROBLEM}
          onRetry={() => void networks.refetch()}
        />
      ) : networks.data.length === 0 ? (
        <EmptyState
          title="No restricted networks"
          description={
            'Create access from an owned VPN client to a granted device.'
          }
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="My networks">
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Ended</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {networks.data.map((network) => (
                <TableRow key={network.id}>
                  <TableCell>
                    {network.id === undefined ? network.source_name : (
                      <Link
                        className="underline"
                        to={`/portal/networks/${network.id}`}
                      >
                        {network.source_name}
                      </Link>
                    )}
                  </TableCell>
                  <TableCell>{network.destination_name}</TableCell>
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

function NetworkDetails({ network }: { network: PortalNetwork }) {
  const close = useClosePortalNetwork()
  const items = [
    ['Source client', network.source_name],
    ['Source VPN address', network.source_virtual_address],
    ['Destination client', network.destination_name],
    ['Destination VPN address', network.destination_virtual_address],
    ['Private destinations', network.private_network_addresses || 'None'],
    ['Started', dateLabel(network.start_time)],
    ['Ended', dateLabel(network.end_time)],
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={`My network ${network.id}`}
        description={
          'Recorded firewall access for your source client. This record ' +
          'does not confirm live connectivity.'
        }
        actions={
          <Button asChild variant="outline">
            <Link to="/portal/networks">Back to my networks</Link>
          </Button>
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>Network details</CardTitle>
          <NetworkStatus network={network} />
        </CardHeader>
        <CardContent>
          <dl className="grid gap-5 sm:grid-cols-2">
            {items.map(([label, value]) => (
              <div key={label}>
                <dt className="text-sm text-muted-foreground">{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      {!network.end_time && network.id !== undefined ? (
        <Card>
          <CardHeader>
            <CardTitle>Close restricted network</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-4 text-sm">
              You can close this access even after the device grant is removed.
              Closing retains the record as history.
            </p>
            <ConfirmActionDialog
              title="Close restricted network?"
              description={
                "Remove this network's firewall access. If closing fails, " +
                'verify the pending operation with an administrator before ' +
                'assuming access has stopped.'
              }
              confirmLabel="Confirm close"
              pendingLabel="Removing firewall rules…"
              trigger={
                <Button type="button" variant="destructive">
                  Close network
                </Button>
              }
              onConfirm={async () => {
                await close.mutateAsync(network.id as number)
                toast.success('Restricted network closed.')
              }}
              onError={() => toast.error(
                'Restricted network could not be closed. Retry or ask an ' +
                'administrator to check pending VPN operations.',
              )}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export function PortalNetworkDetailPage() {
  const { networkId: value } = useParams()
  const id = /^[1-9]\d*$/.test(value ?? '') ? Number(value) : 0
  const valid = id > 0 && Number.isSafeInteger(id)
  const network = usePortalNetwork(id, valid)
  const denied = network.error instanceof ApiProblemError &&
    [403, 404].includes(network.error.problem.status)

  if (!valid || denied) {
    return (
      <div className="space-y-4">
        <ProblemAlert
          problem={{
            type: '/errors/portal-network-denied',
            title: 'Network unavailable',
            status: 403,
            detail: 'This network is unavailable to your account.',
          }}
        />
        <Button asChild variant="outline">
          <Link to="/portal/networks">Back to my networks</Link>
        </Button>
      </div>
    )
  }
  if (network.isPending) {
    return <LoadingTable columns={2} label="Loading my network" />
  }
  if (network.data === undefined) {
    return (
      <ProblemAlert
        problem={NETWORKS_PROBLEM}
        onRetry={() => void network.refetch()}
      />
    )
  }
  return <NetworkDetails network={network.data} />
}
