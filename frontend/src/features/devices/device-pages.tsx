import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  eligibleDeviceClients,
  type Device,
  type VpnClient,
  useCreateDevice,
  useDeleteDevice,
  useDevice,
  useDeviceClients,
  useDevices,
  useUpdateDevice,
} from '@/features/devices/device-api'
import { DeviceForm } from '@/features/devices/device-form'

const LOAD_PROBLEM = {
  type: '/errors/devices-unavailable',
  title: 'Devices unavailable',
  status: 500,
  detail: 'Device data could not be loaded. Try again.',
}

function clientForDevice(
  device: Device,
  clients: VpnClient[],
): VpnClient | undefined {
  return clients.find((client) => client.id === device.client_id)
}

function ProvisioningState({
  device,
  client,
}: {
  device: Device
  client?: VpnClient
}) {
  if (device.client_id === null || device.client_id === undefined) {
    return <StatusBadge label="Not provisioned" tone="neutral" />
  }
  if (client === undefined) {
    return <StatusBadge label="Client unavailable" tone="warning" />
  }
  if (client.revoked) {
    return <StatusBadge label="Client revoked" tone="negative" />
  }
  return <StatusBadge label="Provisioned" tone="positive" />
}

function LoadFailure({ onRetry }: { onRetry: () => void }) {
  return <ProblemAlert onRetry={onRetry} problem={LOAD_PROBLEM} />
}

function MissingDevice() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Device not found"
        description="The requested device does not exist or was removed."
      />
      <Button asChild variant="outline">
        <Link to="/devices">Back to devices</Link>
      </Button>
    </div>
  )
}

function parseDeviceId(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) {
    return null
  }
  const deviceId = Number(value)
  return Number.isSafeInteger(deviceId) && deviceId > 0 ? deviceId : null
}

function isMissingDevice(error: unknown): boolean {
  return (
    error instanceof ApiProblemError && error.problem.status === 404
  )
}

export function DeviceListPage() {
  const devices = useDevices()
  const clients = useDeviceClients()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'devices:write')

  const retry = () => {
    void devices.refetch()
    void clients.refetch()
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Devices"
        description="Manage stable edge-device identities and VPN links."
        actions={
          canWrite ? (
            <Button asChild>
              <Link to="/devices/new">Create device</Link>
            </Button>
          ) : undefined
        }
      />

      {devices.isPending || clients.isPending ? (
        <LoadingTable columns={4} label="Loading devices" />
      ) : devices.data === undefined || clients.data === undefined ? (
        <LoadFailure onRetry={retry} />
      ) : devices.data.length === 0 ? (
        <EmptyState
          title="No devices"
          description="Create a device to register its stable identity."
          action={
            canWrite ? (
              <Button asChild>
                <Link to="/devices/new">Create device</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="Devices">
            <TableHeader>
              <TableRow>
                <TableHead>Device ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Current VPN client</TableHead>
                <TableHead>Provisioning state</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {devices.data.map((device, index) => {
                const client = clientForDevice(device, clients.data)
                const rowKey = device.id ?? `device-${index}`
                return (
                  <TableRow key={rowKey}>
                    <TableCell>{device.id ?? 'Unavailable'}</TableCell>
                    <TableCell className="font-medium">
                      {device.id === null || device.id === undefined ? (
                        device.name
                      ) : (
                        <Link
                          className="underline-offset-4 hover:underline"
                          to={`/devices/${device.id}`}
                        >
                          {device.name}
                        </Link>
                      )}
                    </TableCell>
                    <TableCell>{client?.name ?? 'None'}</TableCell>
                    <TableCell>
                      <ProvisioningState
                        client={client}
                        device={device}
                      />
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

export function CreateDevicePage() {
  const devices = useDevices()
  const clients = useDeviceClients()
  const createDevice = useCreateDevice()
  const navigate = useNavigate()

  if (devices.isPending || clients.isPending) {
    return <LoadingTable columns={2} label="Loading device form" />
  }
  if (devices.data === undefined || clients.data === undefined) {
    return (
      <LoadFailure
        onRetry={() => {
          void devices.refetch()
          void clients.refetch()
        }}
      />
    )
  }

  const eligibleClients = eligibleDeviceClients(
    clients.data,
    devices.data,
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Create device"
        description="Register a device with or without a VPN client."
        actions={
          <Button asChild variant="outline">
            <Link to="/devices">Cancel</Link>
          </Button>
        }
      />
      <Card>
        <CardHeader>
          <p className="text-sm text-muted-foreground">
            Linking a VPN client does not change its certificate status.
          </p>
        </CardHeader>
        <CardContent>
          <DeviceForm
            clients={eligibleClients}
            onSave={async (request) => {
              const created = await createDevice.mutateAsync(request)
              if (created.id === null || created.id === undefined) {
                throw new Error('The created device has no identifier.')
              }
              toast.success('Device created.')
              await navigate(`/devices/${created.id}`)
            }}
            pendingLabel="Creating device…"
            submitLabel="Create device"
          />
        </CardContent>
      </Card>
    </div>
  )
}

interface LoadedDeviceProps {
  device: Device
  clients: VpnClient[]
}

function DeviceDetails({ device, clients }: LoadedDeviceProps) {
  const deleteDevice = useDeleteDevice()
  const navigate = useNavigate()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'devices:write')
  const client = clientForDevice(device, clients)
  const [deleted, setDeleted] = useState(false)

  useEffect(() => {
    if (deleted) {
      void navigate('/devices')
    }
  }, [deleted, navigate])

  return (
    <div className="space-y-6">
      <PageHeader
        title={device.name}
        description="Device identity and its current VPN client link."
        actions={
          <>
            <Button asChild variant="outline">
              <Link to="/devices">Back to devices</Link>
            </Button>
            {canWrite && device.id !== null &&
            device.id !== undefined ? (
              <Button asChild>
                <Link to={`/devices/${device.id}/edit`}>
                  Edit device
                </Link>
              </Button>
            ) : null}
          </>
        }
      />
      <Card>
        <CardContent className="pt-6">
          <dl className="grid gap-5 sm:grid-cols-2">
            <div>
              <dt className="text-sm text-muted-foreground">Device ID</dt>
              <dd className="font-medium">{device.id ?? 'Unavailable'}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">Name</dt>
              <dd className="font-medium">{device.name}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">
                Current VPN client
              </dt>
              <dd className="font-medium">{client?.name ?? 'None'}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">
                Provisioning state
              </dt>
              <dd className="mt-1">
                <ProvisioningState client={client} device={device} />
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>
      {canWrite && device.id !== null && device.id !== undefined ? (
        <Card className="border-red-200">
          <CardHeader>
            <h2 className="text-lg font-semibold">Delete device</h2>
            <p className="text-sm text-muted-foreground">
              Deleting this device does not delete or revoke its VPN client.
            </p>
          </CardHeader>
          <CardContent>
            <ConfirmActionDialog
              confirmLabel="Delete device"
              description={[
                'Deleting this device does not delete or revoke its VPN',
                'client. The client remains available for administration.',
              ].join(' ')}
              onConfirm={async () => {
                await deleteDevice.mutateAsync(device.id as number)
                toast.success('Device deleted. The VPN client was untouched.')
                setDeleted(true)
              }}
              onError={() => toast.error('Device could not be deleted.')}
              pendingLabel="Deleting device…"
              title={`Delete ${device.name}?`}
              trigger={
                <Button type="button" variant="destructive">
                  Delete device
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export function DeviceDetailPage() {
  const { deviceId: deviceIdParam } = useParams()
  const deviceId = parseDeviceId(deviceIdParam)
  const device = useDevice(deviceId ?? 0, deviceId !== null)
  const clients = useDeviceClients()

  if (deviceId === null || isMissingDevice(device.error)) {
    return <MissingDevice />
  }
  if (device.isPending || clients.isPending) {
    return <LoadingTable columns={2} label="Loading device details" />
  }
  if (device.data === undefined || clients.data === undefined) {
    return (
      <LoadFailure
        onRetry={() => {
          void device.refetch()
          void clients.refetch()
        }}
      />
    )
  }
  return <DeviceDetails clients={clients.data} device={device.data} />
}

export function EditDevicePage() {
  const { deviceId: deviceIdParam } = useParams()
  const deviceId = parseDeviceId(deviceIdParam)
  const device = useDevice(deviceId ?? 0, deviceId !== null)
  const devices = useDevices()
  const clients = useDeviceClients()
  const updateDevice = useUpdateDevice()
  const navigate = useNavigate()

  if (deviceId === null || isMissingDevice(device.error)) {
    return <MissingDevice />
  }
  if (device.isPending || devices.isPending || clients.isPending) {
    return <LoadingTable columns={2} label="Loading device form" />
  }
  if (
    device.data === undefined ||
    devices.data === undefined ||
    clients.data === undefined
  ) {
    return (
      <LoadFailure
        onRetry={() => {
          void device.refetch()
          void devices.refetch()
          void clients.refetch()
        }}
      />
    )
  }

  const eligibleClients = eligibleDeviceClients(
    clients.data,
    devices.data,
    device.data.client_id,
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Edit device"
        description={`Update ${device.data.name} or its current VPN client.`}
        actions={
          <Button asChild variant="outline">
            <Link to={`/devices/${deviceId}`}>Cancel</Link>
          </Button>
        }
      />
      <Card>
        <CardHeader>
          <p className="text-sm text-muted-foreground">
            Replacing or unlinking a client does not revoke or delete it.
          </p>
        </CardHeader>
        <CardContent>
          <DeviceForm
            clients={eligibleClients}
            initialClientId={device.data.client_id}
            initialName={device.data.name}
            onSave={async (request) => {
              await updateDevice.mutateAsync({
                deviceId,
                update: request,
              })
              toast.success('Device updated.')
              await navigate(`/devices/${deviceId}`)
            }}
            pendingLabel="Saving changes…"
            submitLabel="Save changes"
          />
        </CardContent>
      </Card>
    </div>
  )
}
