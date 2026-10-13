import { useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { toast } from 'sonner'

import { ApiProblemError } from '@/api/problem-details'
import { EmptyState } from '@/components/shared/empty-state'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  type PortalDevice,
  usePortalClients,
  usePortalCredentialDownload,
  usePortalDevice,
  usePortalDevices,
  useSharedClientConfigDownload,
} from '@/features/portal/portal-api'

const CLIENTS_PROBLEM = {
  type: '/errors/portal-clients-unavailable',
  title: 'VPN clients unavailable',
  status: 500,
  detail: 'Your VPN clients could not be loaded. Try again.',
}
const DEVICES_PROBLEM = {
  type: '/errors/portal-devices-unavailable',
  title: 'Devices unavailable',
  status: 500,
  detail: 'Your authorized devices could not be loaded. Try again.',
}
const DEVICE_PROBLEM = {
  type: '/errors/portal-device-unavailable',
  title: 'Device unavailable',
  status: 403,
  detail: 'This device is unavailable to your account.',
}
const DEVICE_LOAD_PROBLEM = {
  type: '/errors/portal-device-load-failed',
  title: 'Device details unavailable',
  status: 500,
  detail: 'The device details could not be loaded. Try again.',
}

export function PortalLandingPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Device portal"
        description={
          'Use only the VPN clients you own and devices granted to you.'
        }
      />
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>My VPN clients</CardTitle>
            <CardDescription>
              Download credentials for an active laptop VPN client.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild>
              <Link to="/portal/clients">View my VPN clients</Link>
            </Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>My devices</CardTitle>
            <CardDescription>
              Review devices with an explicit application access grant.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild>
              <Link to="/portal/devices">View my devices</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
      <p className="text-sm text-muted-foreground">
        Access shown here is limited to your signed-in account. It does not
        provide identity-management or control-plane administration access.
      </p>
    </div>
  )
}

export function PortalClientsPage() {
  const clients = usePortalClients()
  const download = usePortalCredentialDownload()
  const downloadSharedConfig = useSharedClientConfigDownload()
  const pendingRef = useRef(false)
  const configPendingRef = useRef(false)
  const [pendingClient, setPendingClient] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState(false)
  const [configPending, setConfigPending] = useState(false)
  const [configError, setConfigError] = useState(false)

  async function downloadConfig() {
    if (configPendingRef.current) {
      return
    }
    configPendingRef.current = true
    setConfigPending(true)
    setConfigError(false)
    try {
      await downloadSharedConfig()
      toast.success('Shared OpenVPN profile downloaded.')
    } catch {
      setConfigError(true)
    } finally {
      configPendingRef.current = false
      setConfigPending(false)
    }
  }

  async function downloadCredentials(clientName: string) {
    if (pendingRef.current) {
      return
    }
    pendingRef.current = true
    setPendingClient(clientName)
    setDownloadError(false)
    try {
      await download(clientName)
      toast.success('VPN credentials downloaded.')
    } catch {
      setDownloadError(true)
    } finally {
      pendingRef.current = false
      setPendingClient(null)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="My VPN clients"
        description="Laptop VPN identities assigned to your signed-in account."
        actions={
          <Button asChild variant="outline">
            <Link to="/portal">Back to portal</Link>
          </Button>
        }
      />
      <Card>
        <CardHeader>
          <CardTitle>Connection setup</CardTitle>
          <CardDescription>
            Download the shared OpenVPN profile once. Keep the credential
            archive private, extract its CA, client certificate, and private
            key, and configure those credentials with the shared profile before
            connecting to an authorized device.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1 text-sm">
            <p>
              Put the profile beside the extracted ZIP files. Replace the
              {'<client-name>'} value in the command below, then run it:
            </p>
            <code className="block overflow-x-auto rounded-md bg-muted p-3">
              {'openvpn --config rivet-client.ovpn --ca ca.crt ' +
                '--cert <client-name>.crt --key <client-name>.key'}
            </code>
            <p className="text-muted-foreground">
              In a graphical OpenVPN client, import the shared profile and set
              the same CA, client certificate, and private-key fields.
            </p>
          </div>
          <Button
            aria-label="Download shared OpenVPN profile"
            disabled={configPending}
            onClick={() => void downloadConfig()}
            type="button"
            variant="outline"
          >
            {configPending ? 'Downloading profile…' : 'Download shared profile'}
          </Button>
          {configError ? (
            <p className="text-sm text-red-700" role="alert">
              The shared OpenVPN profile could not be downloaded. Ask an
              administrator to verify the deployment configuration.
            </p>
          ) : null}
        </CardContent>
      </Card>
      {downloadError ? (
        <ProblemAlert
          problem={{
            type: '/errors/credential-download-failed',
            title: 'Credential download failed',
            status: 500,
            detail: 'The credentials could not be downloaded. Try again.',
          }}
        />
      ) : null}
      {clients.isPending ? (
        <LoadingTable columns={3} label="Loading my VPN clients" />
      ) : clients.data === undefined ? (
        <ProblemAlert
          onRetry={() => void clients.refetch()}
          problem={CLIENTS_PROBLEM}
        />
      ) : clients.data.length === 0 ? (
        <EmptyState
          title="No VPN clients assigned"
          description={
            'Ask an administrator to assign a laptop VPN client to ' +
            'your account.'
          }
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="My VPN clients">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead>Credentials</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.data.map((client) => (
                <TableRow key={client.id ?? client.name}>
                  <TableCell>{client.name}</TableCell>
                  <TableCell>
                    <StatusBadge
                      label={client.revoked ? 'Revoked' : 'Active'}
                      tone={client.revoked ? 'negative' : 'positive'}
                    />
                  </TableCell>
                  <TableCell>
                    {client.revoked ? (
                      <span className="text-sm text-muted-foreground">
                        Unavailable for revoked credentials
                      </span>
                    ) : (
                      <Button
                        aria-label={`Download credentials for ${client.name}`}
                        disabled={pendingClient !== null}
                        onClick={() => void downloadCredentials(client.name)}
                        size="sm"
                        type="button"
                        variant="outline"
                      >
                        {pendingClient === client.name
                          ? 'Downloading…'
                          : 'Download'}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}

function EnforcementNotice() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Access status</CardTitle>
        <CardDescription>
          Authorized means an application AccessGrant exists. Not enforced
          means this grant does not apply OpenVPN or firewall policy and does
          not confirm network connectivity.
        </CardDescription>
      </CardHeader>
    </Card>
  )
}

export function PortalDevicesPage() {
  const devices = usePortalDevices()
  return (
    <div className="space-y-6">
      <PageHeader
        title="My devices"
        description="Edge devices explicitly granted to your signed-in account."
        actions={
          <Button asChild variant="outline">
            <Link to="/portal">Back to portal</Link>
          </Button>
        }
      />
      <EnforcementNotice />
      {devices.isPending ? (
        <LoadingTable columns={4} label="Loading my devices" />
      ) : devices.data === undefined ? (
        <ProblemAlert
          onRetry={() => void devices.refetch()}
          problem={DEVICES_PROBLEM}
        />
      ) : devices.data.length === 0 ? (
        <EmptyState
          title="No devices authorized"
          description={
            'Ask an administrator to grant application access to a ' +
            'device.'
          }
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="My devices">
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>Authorization</TableHead>
                <TableHead>Enforcement</TableHead>
                <TableHead>Provisioning</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {devices.data.map((device) => (
                <TableRow key={device.id ?? device.name}>
                  <TableCell>
                    {device.id === null ? (
                      device.name
                    ) : (
                      <Link
                        className="underline-offset-4 hover:underline"
                        to={`/portal/devices/${device.id}`}
                      >
                        {device.name}
                      </Link>
                    )}
                  </TableCell>
                  <TableCell>
                    <StatusBadge label="Authorized" tone="positive" />
                  </TableCell>
                  <TableCell>
                    <StatusBadge label="Not enforced" tone="warning" />
                  </TableCell>
                  <TableCell>
                    {device.client_id === null
                      ? 'Device VPN client not assigned'
                      : 'Device VPN client assigned'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}

function DeviceUnavailable() {
  return (
    <div className="space-y-6">
      <ProblemAlert problem={DEVICE_PROBLEM} />
      <Button asChild variant="outline">
        <Link to="/portal/devices">Back to my devices</Link>
      </Button>
    </div>
  )
}

function DeviceLoadFailure({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="space-y-6">
      <ProblemAlert onRetry={onRetry} problem={DEVICE_LOAD_PROBLEM} />
      <Button asChild variant="outline">
        <Link to="/portal/devices">Back to my devices</Link>
      </Button>
    </div>
  )
}

function PortalDeviceDetails({ device }: { device: PortalDevice }) {
  return (
    <div className="space-y-6">
      <PageHeader
        title={device.name}
        description="Your application access to this edge device."
        actions={
          <Button asChild variant="outline">
            <Link to="/portal/devices">Back to my devices</Link>
          </Button>
        }
      />
      <Card>
        <CardContent className="grid gap-5 pt-6 sm:grid-cols-3">
          <div>
            <p className="text-sm text-muted-foreground">Authorization</p>
            <StatusBadge label="Authorized" tone="positive" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Enforcement</p>
            <StatusBadge label="Not enforced" tone="warning" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Device VPN identity</p>
            <p>{device.client_id === null ? 'Not assigned' : 'Assigned'}</p>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Connection instructions</CardTitle>
          <CardDescription>
            Connect using one of your active laptop VPN clients. An
            administrator must separately configure OpenVPN and firewall policy
            before this device is reachable; this page does not guarantee
            connectivity.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  )
}

export function PortalDeviceDetailPage() {
  const { deviceId: value } = useParams()
  const canonicalDeviceId = /^[1-9]\d*$/.test(value ?? '')
  const deviceId = canonicalDeviceId ? Number(value) : 0
  const validDeviceId = canonicalDeviceId && Number.isSafeInteger(deviceId)
  const device = usePortalDevice(deviceId, validDeviceId)

  if (!validDeviceId) {
    return <DeviceUnavailable />
  }
  if (device.isPending) {
    return <LoadingTable columns={2} label="Loading device details" />
  }
  if (
    device.error instanceof ApiProblemError &&
    device.error.problem.status === 403
  ) {
    return <DeviceUnavailable />
  }
  if (device.data === undefined) {
    return (
      <DeviceLoadFailure onRetry={() => void device.refetch()} />
    )
  }
  return <PortalDeviceDetails device={device.data} />
}
