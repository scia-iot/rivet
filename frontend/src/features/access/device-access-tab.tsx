import { useRef, useState } from 'react'
import { Link } from 'react-router'
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
  useGrantDeviceAccess,
  useRevokeDeviceAccess,
  useUserDevices,
} from '@/features/access/access-api'
import { useDevices } from '@/features/devices/device-api'

const ACCESS_LOAD_PROBLEM = {
  type: '/errors/access-unavailable',
  title: 'Device access unavailable',
  status: 500,
  detail: 'Device authorization data could not be loaded. Try again.',
}

function isMissing(error: unknown): boolean {
  return error instanceof ApiProblemError && error.problem.status === 404
}

function AuthorizationExplanation() {
  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">
          Application authorization only
        </h2>
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-muted-foreground">
        <p>
          <strong className="text-foreground">Authorized</strong> means an
          AccessGrant record exists for this user and device.
        </p>
        <p>
          <strong className="text-foreground">
            Enforced: Not enforced.
          </strong>{' '}
          rivet does not apply OpenVPN or firewall policy for these grants and
          does not confirm network connectivity.
        </p>
      </CardContent>
    </Card>
  )
}

function AccessPermissionNotice() {
  return (
    <div className="space-y-5">
      <AuthorizationExplanation />
      <Card>
        <CardHeader>
          <h2 className="text-lg font-semibold">Device access</h2>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            The access:read permission is required to review AccessGrant
            records.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

function AccessManager({
  canGrant,
  userId,
}: {
  canGrant: boolean
  userId: number
}) {
  const authorized = useUserDevices(userId)
  const choices = useDevices(canGrant)
  const grant = useGrantDeviceAccess()
  const revoke = useRevokeDeviceAccess()
  const [selected, setSelected] = useState('')
  const [error, setError] = useState<string | null>(null)
  const actionRef = useRef(false)

  if (authorized.isPending || (canGrant && choices.isPending)) {
    return <LoadingTable columns={4} label="Loading device access" />
  }
  if (
    authorized.data === undefined ||
    (canGrant && choices.data === undefined)
  ) {
    return (
      <ProblemAlert
        onRetry={() => {
          void authorized.refetch()
          if (canGrant) {
            void choices.refetch()
          }
        }}
        problem={ACCESS_LOAD_PROBLEM}
      />
    )
  }

  const authorizedIds = new Set(
    authorized.data.flatMap((device) =>
      device.id === null || device.id === undefined ? [] : [device.id],
    ),
  )
  const eligible = (choices.data ?? []).filter(
    (device) =>
      device.id !== null &&
      device.id !== undefined &&
      !authorizedIds.has(device.id),
  )

  async function grantAccess() {
    if (!selected || actionRef.current) {
      return
    }
    actionRef.current = true
    setError(null)
    try {
      await grant.mutateAsync({
        userId,
        deviceId: Number(selected),
      })
      setSelected('')
      toast.success('Application access authorized.')
    } catch (reason: unknown) {
      setError(
        isMissing(reason)
          ? 'The user or device no longer exists.'
          : 'Device access could not be granted. Try again.',
      )
    } finally {
      actionRef.current = false
    }
  }

  function revokeError(reason: unknown) {
    setError(
      isMissing(reason)
        ? 'The access grant no longer exists.'
        : 'Device access could not be revoked. Try again.',
    )
  }

  return (
    <div className="space-y-5">
      <AuthorizationExplanation />
      {canGrant ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Grant device access</h2>
            <p className="text-sm text-muted-foreground">
              Only devices without an existing AccessGrant are available.
            </p>
          </CardHeader>
          <CardContent className="flex max-w-2xl flex-col gap-3 sm:flex-row">
            <EntitySelect
              id="user-device"
              emptyText="No devices without access grants found."
              label="Device"
              onValueChange={setSelected}
              options={eligible.map((device) => ({
                value: String(device.id),
                label: device.name,
              }))}
              placeholder="Select a device"
              searchPlaceholder="Search devices"
              value={selected}
            />
            <Button
              disabled={!selected || grant.isPending}
              onClick={() => void grantAccess()}
              type="button"
            >
              {grant.isPending ? 'Granting…' : 'Grant access'}
            </Button>
          </CardContent>
        </Card>
      ) : null}
      {error ? (
        <p className="text-sm text-red-700" role="alert">
          {error}
        </p>
      ) : null}
      {authorized.data.length === 0 ? (
        <EmptyState
          title="No authorized devices"
          description="This user has no application-level device grants."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="Authorized devices">
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>Authorization</TableHead>
                <TableHead>Network enforcement</TableHead>
                <TableHead>Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {authorized.data.map((device, index) => (
                <TableRow key={device.id ?? `authorized-device-${index}`}>
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
                  <TableCell>
                    <StatusBadge label="Authorized" tone="positive" />
                  </TableCell>
                  <TableCell>
                    <StatusBadge label="Not enforced" tone="warning" />
                  </TableCell>
                  <TableCell>
                    {!canGrant ||
                    device.id === null ||
                    device.id === undefined ? null : (
                      <ConfirmActionDialog
                        confirmLabel="Revoke access"
                        description={
                          'Remove this application authorization record. ' +
                          'This does not change OpenVPN or firewall policy.'
                        }
                        onConfirm={async () => {
                          setError(null)
                          await revoke.mutateAsync({
                            userId,
                            deviceId: device.id as number,
                          })
                          toast.success('Application access revoked.')
                        }}
                        onError={revokeError}
                        pendingLabel="Revoking…"
                        title={`Revoke access to ${device.name}?`}
                        trigger={
                          <Button
                            aria-label={`Revoke access for ${device.name}`}
                            disabled={revoke.isPending}
                            type="button"
                            variant="outline"
                          >
                            Revoke
                          </Button>
                        }
                      />
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

export function DeviceAccessTab({ userId }: { userId: number }) {
  const session = usePrincipalSession()
  if (!hasPermission(session, 'access:read')) {
    return <AccessPermissionNotice />
  }
  return (
    <AccessManager
      canGrant={hasPermission(session, 'access:grant')}
      userId={userId}
    />
  )
}
