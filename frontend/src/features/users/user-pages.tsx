import { useEffect, useRef, useState } from 'react'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs'
import {
  type User,
  useAllUserClients,
  useCreateUser,
  useDeleteUser,
  useLinkUserClient,
  useUnlinkUserClient,
  useUpdateUser,
  useUser,
  useUserClientChoices,
  useUserClients,
  useUsers,
} from '@/features/users/user-api'
import { UserForm } from '@/features/users/user-form'

const LOAD_PROBLEM = {
  type: '/errors/users-unavailable',
  title: 'Users unavailable',
  status: 500,
  detail: 'User data could not be loaded. Try again.',
}

function parseUserId(value: string | undefined): number | null {
  if (value === undefined || !/^\d+$/.test(value)) {
    return null
  }
  const userId = Number(value)
  return Number.isSafeInteger(userId) && userId > 0 ? userId : null
}

function isMissing(error: unknown): boolean {
  return error instanceof ApiProblemError && error.problem.status === 404
}

function LoadFailure({ onRetry }: { onRetry: () => void }) {
  return <ProblemAlert onRetry={onRetry} problem={LOAD_PROBLEM} />
}

function MissingUser() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="User not found"
        description="The requested user does not exist or was removed."
      />
      <Button asChild variant="outline">
        <Link to="/users">Back to users</Link>
      </Button>
    </div>
  )
}

export function UserListPage() {
  const users = useUsers()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'users:write')

  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Manage local users backed by external identities."
        actions={
          canWrite ? (
            <Button asChild>
              <Link to="/users/new">Create user</Link>
            </Button>
          ) : undefined
        }
      />
      {users.isPending ? (
        <LoadingTable columns={2} label="Loading users" />
      ) : users.data === undefined ? (
        <LoadFailure onRetry={() => void users.refetch()} />
      ) : users.data.length === 0 ? (
        <EmptyState
          title="No users"
          description="Create a user to map an external identity."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="Users">
            <TableHeader>
              <TableRow>
                <TableHead>User ID</TableHead>
                <TableHead>Display name</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.data.map((user, index) => (
                <TableRow key={user.id ?? `user-${index}`}>
                  <TableCell>{user.id ?? 'Unavailable'}</TableCell>
                  <TableCell className="font-medium">
                    {user.id === null || user.id === undefined ? (
                      user.display_name
                    ) : (
                      <Link
                        className="underline-offset-4 hover:underline"
                        to={`/users/${user.id}`}
                      >
                        {user.display_name}
                      </Link>
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

export function CreateUserPage() {
  const createUser = useCreateUser()
  const navigate = useNavigate()
  return (
    <div className="space-y-6">
      <PageHeader
        title="Create user"
        description="Map a local user to a validated external identity."
        actions={
          <Button asChild variant="outline">
            <Link to="/users">Cancel</Link>
          </Button>
        }
      />
      <Card>
        <CardContent className="pt-6">
          <UserForm
            identityEditable
            onSave={async (request) => {
              const created = await createUser.mutateAsync(request)
              if (created.id === null || created.id === undefined) {
                throw new Error('The created user has no identifier.')
              }
              toast.success('User created.')
              await navigate(`/users/${created.id}`)
            }}
            pendingLabel="Creating user…"
            submitLabel="Create user"
          />
        </CardContent>
      </Card>
    </div>
  )
}

function UserOverview({ user, canWrite }: { user: User; canWrite: boolean }) {
  return (
    <Card>
      <CardContent className="pt-6">
        <dl className="grid gap-5 sm:grid-cols-2">
          <div>
            <dt className="text-sm text-muted-foreground">User ID</dt>
            <dd className="font-medium">{user.id ?? 'Unavailable'}</dd>
          </div>
          <div>
            <dt className="text-sm text-muted-foreground">Display name</dt>
            <dd className="font-medium">{user.display_name}</dd>
          </div>
          {canWrite ? (
            <>
              <div>
                <dt className="text-sm text-muted-foreground">Issuer</dt>
                <dd className="break-all font-medium">{user.issuer}</dd>
              </div>
              <div>
                <dt className="text-sm text-muted-foreground">Subject</dt>
                <dd className="break-all font-medium">{user.subject}</dd>
              </div>
            </>
          ) : null}
        </dl>
      </CardContent>
    </Card>
  )
}

function UserClientsTab({
  userId,
  canWrite,
}: {
  userId: number
  canWrite: boolean
}) {
  const users = useUsers()
  const assigned = useUserClients(userId)
  const choices = useUserClientChoices()
  const ownership = useAllUserClients(users.data)
  const linkClient = useLinkUserClient()
  const unlinkClient = useUnlinkUserClient()
  const [selected, setSelected] = useState('')
  const [error, setError] = useState<string | null>(null)
  const actionRef = useRef(false)

  if (
    users.isPending ||
    assigned.isPending ||
    choices.isPending ||
    (users.data !== undefined && ownership.isPending)
  ) {
    return <LoadingTable columns={3} label="Loading user VPN clients" />
  }
  if (
    users.data === undefined ||
    assigned.data === undefined ||
    choices.data === undefined ||
    ownership.data === undefined
  ) {
    return (
      <LoadFailure
        onRetry={() => {
          void users.refetch()
          void assigned.refetch()
          void choices.refetch()
          if (users.data !== undefined) {
            void ownership.refetch()
          }
        }}
      />
    )
  }

  const assignedIds = new Set(assigned.data.map((item) => item.id))
  const ownedElsewhere = new Set(
    ownership.data
      .filter((item) => item.userId !== userId)
      .map((item) => item.clientId),
  )
  const eligible = choices.data.filter(
    (item) =>
      item.id !== undefined &&
      !assignedIds.has(item.id) &&
      !ownedElsewhere.has(item.id),
  )

  async function assign() {
    if (!selected || actionRef.current) {
      return
    }
    actionRef.current = true
    setError(null)
    try {
      await linkClient.mutateAsync({ userId, clientId: Number(selected) })
      setSelected('')
      toast.success('VPN client assigned.')
    } catch (reason: unknown) {
      if (reason instanceof ApiProblemError && reason.problem.status === 409) {
        setError('This VPN client is assigned to another user.')
      } else if (
        reason instanceof ApiProblemError &&
        reason.problem.status === 404
      ) {
        setError('The user or VPN client no longer exists.')
      } else {
        setError('The VPN client could not be assigned. Try again.')
      }
    } finally {
      actionRef.current = false
    }
  }

  async function unlink(clientId: number) {
    if (actionRef.current) {
      return
    }
    actionRef.current = true
    setError(null)
    try {
      await unlinkClient.mutateAsync({ userId, clientId })
      toast.success('VPN client unlinked. Certificate untouched.')
    } catch {
      setError('The VPN client could not be unlinked.')
    } finally {
      actionRef.current = false
    }
  }

  return (
    <div className="space-y-5">
      {canWrite ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Assign VPN client</h2>
            <p className="text-sm text-muted-foreground">
              Only unowned clients are available. Assignment does not change
              certificate status.
            </p>
          </CardHeader>
          <CardContent className="flex max-w-2xl flex-col gap-3 sm:flex-row">
            <EntitySelect
              id="user-client"
              emptyText="No unowned VPN clients found."
              label="VPN client"
              onValueChange={setSelected}
              options={eligible.map((item) => ({
                value: String(item.id),
                label: item.revoked ? `${item.name} (revoked)` : item.name,
              }))}
              placeholder="Select a VPN client"
              searchPlaceholder="Search VPN clients"
              value={selected}
            />
            <Button
              disabled={!selected || linkClient.isPending}
              onClick={() => void assign()}
              type="button"
            >
              {linkClient.isPending ? 'Assigning…' : 'Assign client'}
            </Button>
          </CardContent>
          {error ? (
            <p className="px-6 pb-6 text-sm text-red-700" role="alert">
              {error}
            </p>
          ) : null}
        </Card>
      ) : null}
      {assigned.data.length === 0 ? (
        <EmptyState
          title="No assigned VPN clients"
          description="Assign one or more laptop VPN clients to this user."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="User VPN clients">
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Certificate</TableHead>
                <TableHead>Assignment</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assigned.data.map((vpnClient) => (
                <TableRow key={vpnClient.id ?? vpnClient.name}>
                  <TableCell>
                    <Link
                      className="underline-offset-4 hover:underline"
                      to={`/clients/${encodeURIComponent(vpnClient.name)}`}
                    >
                      {vpnClient.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <StatusBadge
                      label={vpnClient.revoked ? 'Revoked' : 'Active'}
                      tone={vpnClient.revoked ? 'negative' : 'positive'}
                    />
                  </TableCell>
                  <TableCell>
                    {!canWrite || vpnClient.id === undefined ? null : (
                      <Button
                        disabled={unlinkClient.isPending}
                        onClick={() => void unlink(vpnClient.id as number)}
                        type="button"
                        variant="outline"
                      >
                        Unlink
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

function UserDetails({ user }: { user: User }) {
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'users:write')
  const deleteUser = useDeleteUser()
  const navigate = useNavigate()
  const [deleted, setDeleted] = useState(false)

  useEffect(() => {
    if (deleted) {
      void navigate('/users')
    }
  }, [deleted, navigate])

  return (
    <div className="space-y-6">
      <PageHeader
        title={user.display_name}
        description="User identity, owned VPN clients, and device access."
        actions={
          <>
            <Button asChild variant="outline">
              <Link to="/users">Back to users</Link>
            </Button>
            {canWrite && user.id !== null && user.id !== undefined ? (
              <Button asChild>
                <Link to={`/users/${user.id}/edit`}>Rename user</Link>
              </Button>
            ) : null}
          </>
        }
      />
      <Tabs defaultValue="overview">
        <TabsList aria-label="User details">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="clients">VPN clients</TabsTrigger>
          <TabsTrigger value="access">Device access</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <UserOverview canWrite={canWrite} user={user} />
        </TabsContent>
        <TabsContent value="clients">
          {user.id === null || user.id === undefined ? null : (
            <UserClientsTab canWrite={canWrite} userId={user.id} />
          )}
        </TabsContent>
        <TabsContent value="access">
          <Card>
            <CardHeader>
              <h2 className="text-lg font-semibold">Device access</h2>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                Device access management is not available in this phase.
                Existing application grants are not presented as enforced
                network access.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
      {canWrite && user.id !== null && user.id !== undefined ? (
        <Card className="border-red-200">
          <CardHeader>
            <h2 className="text-lg font-semibold">Delete user</h2>
            <p className="text-sm text-muted-foreground">
              Deleting this user unlinks owned VPN clients. It does not delete
              or revoke those clients.
            </p>
          </CardHeader>
          <CardContent>
            <ConfirmActionDialog
              confirmLabel="Delete user"
              description={
                'The user and local grants will be deleted. Owned VPN ' +
                'clients remain available and their certificates stay ' +
                'unchanged.'
              }
              onConfirm={async () => {
                await deleteUser.mutateAsync(user.id as number)
                toast.success('User deleted. VPN clients were untouched.')
                setDeleted(true)
              }}
              onError={() => toast.error('User could not be deleted.')}
              pendingLabel="Deleting user…"
              title={`Delete ${user.display_name}?`}
              trigger={
                <Button type="button" variant="destructive">
                  Delete user
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export function UserDetailPage() {
  const { userId: value } = useParams()
  const userId = parseUserId(value)
  const user = useUser(userId ?? 0, userId !== null)
  if (userId === null || isMissing(user.error)) {
    return <MissingUser />
  }
  if (user.isPending) {
    return <LoadingTable columns={2} label="Loading user details" />
  }
  if (user.data === undefined) {
    return <LoadFailure onRetry={() => void user.refetch()} />
  }
  return <UserDetails user={user.data} />
}

export function EditUserPage() {
  const { userId: value } = useParams()
  const userId = parseUserId(value)
  const user = useUser(userId ?? 0, userId !== null)
  const updateUser = useUpdateUser()
  const navigate = useNavigate()
  if (userId === null || isMissing(user.error)) {
    return <MissingUser />
  }
  if (user.isPending) {
    return <LoadingTable columns={1} label="Loading user form" />
  }
  if (user.data === undefined) {
    return <LoadFailure onRetry={() => void user.refetch()} />
  }
  return (
    <div className="space-y-6">
      <PageHeader
        title="Rename user"
        description={
          'Update the local display name for ' +
          `${user.data.display_name}.`
        }
        actions={
          <Button asChild variant="outline">
            <Link to={`/users/${userId}`}>Cancel</Link>
          </Button>
        }
      />
      <Card>
        <CardContent className="pt-6">
          <UserForm
            initialName={user.data.display_name}
            issuer={user.data.issuer}
            subject={user.data.subject}
            onSave={async (request) => {
              await updateUser.mutateAsync({
                userId,
                update: { display_name: request.display_name },
              })
              toast.success('User renamed.')
              await navigate(`/users/${userId}`)
            }}
            pendingLabel="Saving…"
            submitLabel="Save name"
          />
        </CardContent>
      </Card>
    </div>
  )
}
