import { useRef, useState } from 'react'

import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { LoadingTable } from '@/components/shared/loading-table'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  useBatchGrantDeviceAccess,
  useDeviceAccessGrants,
} from '@/features/access/access-api'
import { useUsers } from '@/features/users/user-api'

const LOAD_PROBLEM = {
  type: '/errors/device-access-unavailable',
  title: 'User access unavailable',
  status: 500,
  detail: 'User access could not be loaded. Try again.',
}

function AccessManager({
  deviceId,
  canReadUsers,
  canGrant,
}: {
  deviceId: number
  canReadUsers: boolean
  canGrant: boolean
}) {
  const grants = useDeviceAccessGrants(deviceId)
  const users = useUsers(canReadUsers)
  const batch = useBatchGrantDeviceAccess()
  const [selected, setSelected] = useState<number[]>([])
  const [search, setSearch] = useState('')
  const [error, setError] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const locked = useRef(false)

  const assigned = new Set(
    (grants.data ?? []).map((grant) => grant.user_id),
  )
  const eligible = (users.data ?? []).filter(
    (user) => user.id != null && !assigned.has(user.id),
  )
  const selectedIds = selected.filter((id) =>
    eligible.some((user) => user.id === id),
  )
  const filtered = eligible.filter((user) =>
    `${user.display_name} ${user.id}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  )

  function label(id: number) {
    const user = canReadUsers
      ? users.data?.find((item) => item.id === id)
      : undefined
    return user ? `${user.display_name} (ID ${id})` : `User ID ${id}`
  }

  async function grantAccess() {
    if (
      locked.current ||
      selectedIds.length === 0 ||
      selectedIds.length > 100
    ) {
      return
    }
    locked.current = true
    setError(false)
    setResult(null)
    try {
      const saved = await batch.mutateAsync({
        deviceId,
        userIds: selectedIds,
      })
      setSelected([])
      setResult(
        `${saved.created} granted; ` +
          `${saved.already_granted} already authorized.`,
      )
    } catch {
      setError(true)
    } finally {
      locked.current = false
    }
  }

  if (grants.isPending || (canReadUsers && users.isPending)) {
    return <LoadingTable columns={1} label="Loading user access" />
  }
  if (
    grants.isError ||
    grants.data === undefined ||
    (canReadUsers && (users.isError || users.data === undefined))
  ) {
    return (
      <ProblemAlert
        problem={LOAD_PROBLEM}
        onRetry={() => {
          void grants.refetch()
          if (canReadUsers) void users.refetch()
        }}
      />
    )
  }

  return (
    <div className="space-y-4">
      <h3 className="font-medium">Authorized users</h3>
      {grants.data.length > 0 ? (
        <ul className="list-disc pl-5">
          {grants.data.map((grant) => (
            <li key={grant.user_id}>{label(grant.user_id)}</li>
          ))}
        </ul>
      ) : (
        <p>No users are authorized for this device.</p>
      )}
      {canGrant ? (
        <div className="space-y-3">
          <h3 className="font-medium">Grant device access</h3>
          <Input
            aria-label="Search users"
            placeholder="Search users by name or ID"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <fieldset
            disabled={batch.isPending}
            className="max-h-64 space-y-2 overflow-y-auto rounded-md border p-3"
          >
            <legend className="px-1 text-sm">
              Select users (up to 100)
            </legend>
            {filtered.map((user) => {
              const id = user.id as number
              const checked = selectedIds.includes(id)
              return (
                <label
                  key={id}
                  className="flex items-center gap-2 text-sm"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={selectedIds.length >= 100 && !checked}
                    onChange={(event) => {
                      const isChecked = event.target.checked
                      setSelected((current) =>
                        isChecked
                          ? [...current, id]
                          : current.filter((item) => item !== id),
                      )
                    }}
                  />
                  {label(id)}
                </label>
              )
            })}
            {eligible.length === 0 ? (
              <p>No additional users are available.</p>
            ) : filtered.length === 0 ? (
              <p>No users match your search.</p>
            ) : null}
          </fieldset>
          <p className="text-sm text-muted-foreground">
            {selectedIds.length} of 100 users selected
          </p>
          {error ? (
            <p role="alert" className="text-sm text-red-700">
              Access could not be granted. Try again.
            </p>
          ) : null}
          <Button
            disabled={batch.isPending || selectedIds.length === 0}
            onClick={() => void grantAccess()}
          >
            {batch.isPending ? 'Granting access…' : 'Grant access'}
          </Button>
        </div>
      ) : null}
      {result ? <p role="status">{result}</p> : null}
    </div>
  )
}

export function DeviceUserAccess({ deviceId }: { deviceId: number }) {
  const session = usePrincipalSession()
  const canRead = hasPermission(session, 'access:read')
  const canReadUsers = hasPermission(session, 'users:read')
  const canGrant = canReadUsers && hasPermission(session, 'access:grant')

  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">User access</h2>
        <p className="text-sm text-muted-foreground">
          Authorized users can create networks from their own VPN clients
          to this device. Granting access does not create a network
          automatically.
        </p>
      </CardHeader>
      <CardContent>
        {canRead ? (
          <AccessManager
            key={deviceId}
            deviceId={deviceId}
            canReadUsers={canReadUsers}
            canGrant={canGrant}
          />
        ) : (
          <p>
            The access:read permission is required to review user access.
          </p>
        )}
      </CardContent>
    </Card>
  )
}
