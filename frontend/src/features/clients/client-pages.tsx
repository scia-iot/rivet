import { useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'

import { ApiProblemError } from '@/api/problem-details'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { EmptyState } from '@/components/shared/empty-state'
import { EntitySelect } from '@/components/shared/entity-select'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
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
import {
  certificateExpiryLabel,
  type VpnClientDetails,
  useAssignableAddresses,
  useAssignVirtualAddress,
  useCertificateDownload,
  useClientDetails,
  useClients,
  useCreateClient,
  useDeleteClient,
  useImportClients,
  usePackageCertificate,
  useRenewCertificate,
  useRevokeCertificate,
  useUnassignVirtualAddress,
} from '@/features/clients/client-api'
import { DeleteClientDialog } from '@/features/clients/delete-client-dialog'
import {
  RevokeCertificateDialog,
} from '@/features/clients/revoke-certificate-dialog'

const LOAD_PROBLEM = {
  type: '/errors/clients-unavailable',
  title: 'VPN clients unavailable',
  status: 500,
  detail: 'VPN client data could not be loaded. Try again.',
}

function LoadFailure({ onRetry }: { onRetry: () => void }) {
  return <ProblemAlert onRetry={onRetry} problem={LOAD_PROBLEM} />
}

function CertificateStatus({ revoked }: { revoked: boolean }) {
  return (
    <StatusBadge
      label={revoked ? 'Revoked' : 'Active'}
      tone={revoked ? 'negative' : 'positive'}
    />
  )
}

function CreateClientForm() {
  const createClient = useCreateClient()
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const pendingRef = useRef(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (pendingRef.current) {
      return
    }
    const normalized = name.trim()
    if (!normalized) {
      setError('Enter a client name.')
      return
    }
    pendingRef.current = true
    setError(null)
    try {
      await createClient.mutateAsync({
        name: normalized,
        cidr: null,
        revoked: false,
      })
      setName('')
      toast.success('VPN client created.')
    } catch {
      setError('The VPN client could not be created. Try again.')
    } finally {
      pendingRef.current = false
    }
  }

  return (
    <form className="flex flex-col gap-3 sm:flex-row" onSubmit={submit}>
      <Field className="grow">
        <FieldLabel htmlFor="client-name">Client name</FieldLabel>
        <Input
          aria-describedby={error ? 'client-name-error' : undefined}
          aria-invalid={error ? true : undefined}
          autoComplete="off"
          id="client-name"
          onChange={(event) => setName(event.target.value)}
          required
          value={name}
        />
        {error ? <FieldError id="client-name-error">{error}</FieldError> : null}
      </Field>
      <Button className="self-end" disabled={createClient.isPending}>
        {createClient.isPending ? 'Creating…' : 'Create client'}
      </Button>
    </form>
  )
}

export function ClientListPage() {
  const clients = useClients()
  const importClients = useImportClients()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'clients:write')
  const [importResult, setImportResult] = useState<string | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [createDevices, setCreateDevices] = useState(false)
  const [importPending, setImportPending] = useState(false)
  const [importError, setImportError] = useState(false)
  const importRef = useRef(false)

  function changeImportOpen(nextOpen: boolean) {
    if (importRef.current && !nextOpen) {
      return
    }
    setImportOpen(nextOpen)
    if (nextOpen) {
      setCreateDevices(false)
      setImportError(false)
    }
  }

  async function importExisting() {
    if (importRef.current) {
      return
    }
    importRef.current = true
    setImportPending(true)
    setImportError(false)
    setImportResult(null)
    try {
      const result = await importClients.mutateAsync({
        create_devices: createDevices,
      })
      const clientCounts =
        `Clients: ${result.added} added, ${result.updated} updated, ` +
        `${result.clients_skipped} skipped.`
      const deviceCounts =
        ` Devices: ${result.devices_created} created, ` +
        `${result.devices_already_linked} already linked, ` +
        `${result.device_conflicts} conflicts.`
      setImportResult(
        createDevices ? `${clientCounts}${deviceCounts}` : clientCounts,
      )
      toast.success('VPN client import completed.')
      importRef.current = false
      setImportPending(false)
      setImportOpen(false)
    } catch {
      setImportError(true)
    } finally {
      importRef.current = false
      setImportPending(false)
    }
  }


  return (
    <div className="space-y-6">
      <PageHeader
        title="VPN clients"
        description="Provision and maintain OpenVPN client identities."
        actions={
          canWrite ? (
            <Dialog onOpenChange={changeImportOpen} open={importOpen}>
              <DialogTrigger asChild>
                <Button type="button" variant="outline">
                  Import clients
                </Button>
              </DialogTrigger>
              <DialogContent showCloseButton={!importPending}>
                <DialogHeader>
                  <DialogTitle>Import VPN clients</DialogTitle>
                  <DialogDescription>
                    This will scan all existing Easy-RSA client certificates
                    and import every valid VPN client.
                  </DialogDescription>
                </DialogHeader>
                <div className="flex items-center gap-2">
                  <input
                    checked={createDevices}
                    disabled={importPending}
                    id="create-import-devices"
                    onChange={(event) =>
                      setCreateDevices(event.target.checked)
                    }
                    type="checkbox"
                  />
                  <label htmlFor="create-import-devices">
                    Create matching edge devices
                  </label>
                </div>
                {importError ? (
                  <p className="text-sm text-red-700" role="alert">
                    VPN clients could not be imported. Review the certificates
                    and try again.
                  </p>
                ) : null}
                <DialogFooter>
                  <DialogClose asChild>
                    <Button
                      disabled={importPending}
                      type="button"
                      variant="outline"
                    >
                      Cancel
                    </Button>
                  </DialogClose>
                  <Button
                    disabled={importPending}
                    onClick={() => void importExisting()}
                    type="button"
                  >
                    {importPending ? 'Importing…' : 'Import clients'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          ) : undefined
        }
      />
      {canWrite ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Create VPN client</h2>
          </CardHeader>
          <CardContent>
            <CreateClientForm />
          </CardContent>
        </Card>
      ) : null}
      {importResult ? <p role="status">{importResult}</p> : null}
      {clients.isPending ? (
        <LoadingTable columns={4} label="Loading VPN clients" />
      ) : clients.data === undefined ? (
        <LoadFailure onRetry={() => void clients.refetch()} />
      ) : clients.data.length === 0 ? (
        <EmptyState
          title="No VPN clients"
          description="Create or import a VPN client to begin."
        />
      ) : (
        <div className="rounded-md border">
          <Table aria-label="VPN clients">
            <TableHeader>
              <TableRow>
                <TableHead>Client ID</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Network</TableHead>
                <TableHead>Certificate</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.data.map((client) => (
                <TableRow key={client.id ?? client.name}>
                  <TableCell>{client.id ?? 'Unavailable'}</TableCell>
                  <TableCell>
                    <Link
                      className="underline-offset-4 hover:underline"
                      to={`/clients/${encodeURIComponent(client.name)}`}
                    >
                      {client.name}
                    </Link>
                  </TableCell>
                  <TableCell>{client.cidr ?? 'None'}</TableCell>
                  <TableCell>
                    <CertificateStatus revoked={client.revoked} />
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

function MissingClient() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="VPN client not found"
        description="The requested VPN client does not exist."
      />
      <Button asChild variant="outline">
        <Link to="/clients">Back to VPN clients</Link>
      </Button>
    </div>
  )
}

function isMissing(error: unknown): boolean {
  return error instanceof ApiProblemError && error.problem.status === 404
}

function ClientAddressCard({
  client,
  canWrite,
}: {
  client: VpnClientDetails
  canWrite: boolean
}) {
  const addresses = useAssignableAddresses(
    canWrite && !client.revoked && client.virtual_address === null,
  )
  const assign = useAssignVirtualAddress()
  const unassign = useUnassignVirtualAddress()
  const [selected, setSelected] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [addressPending, setAddressPending] = useState(false)
  const pendingRef = useRef(false)

  async function assignAddress() {
    if (!selected || pendingRef.current) {
      return
    }
    pendingRef.current = true
    setAddressPending(true)
    setError(null)
    try {
      await assign.mutateAsync({ clientName: client.name, ip: selected })
      setSelected('')
      toast.success('Virtual address assigned.')
    } catch (reason: unknown) {
      setError(
        reason instanceof ApiProblemError && reason.problem.status === 409
          ? 'This virtual address is assigned to another client.'
          : 'The virtual address could not be assigned. Try again.',
      )
    } finally {
      pendingRef.current = false
      setAddressPending(false)
    }
  }

  async function unassignAddress() {
    if (pendingRef.current) {
      return
    }
    pendingRef.current = true
    setAddressPending(true)
    setError(null)
    try {
      await unassign.mutateAsync(client.name)
      toast.success('Virtual address unassigned.')
    } catch {
      setError('The virtual address could not be unassigned.')
    } finally {
      pendingRef.current = false
      setAddressPending(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <h2 className="text-lg font-semibold">Virtual address</h2>
        <p className="text-sm text-muted-foreground">
          Current address: {client.virtual_address?.ip ?? 'None'}
        </p>
      </CardHeader>
      {canWrite ? (
        <CardContent className="space-y-3">
          {client.virtual_address ? (
            <Button
              disabled={addressPending}
              onClick={() => void unassignAddress()}
              type="button"
              variant="outline"
            >
              {addressPending ? 'Updating address…' : 'Unassign address'}
            </Button>
          ) : client.revoked ? (
            <p className="text-sm text-muted-foreground">
              Revoked VPN clients cannot be assigned virtual addresses.
            </p>
          ) : addresses.isPending ? (
            <p aria-live="polite" role="status">
              Loading assignable addresses…
            </p>
          ) : addresses.data === undefined ? (
            <LoadFailure onRetry={() => void addresses.refetch()} />
          ) : (
            <div className="flex flex-col gap-3 sm:flex-row">
              <EntitySelect
                id="client-address"
                emptyText="No assignable virtual addresses found."
                label="Virtual address"
                onValueChange={setSelected}
                options={addresses.data.map((address) => ({
                  value: address.ip,
                  label: address.ip,
                }))}
                placeholder="Select an address"
                searchPlaceholder="Search virtual addresses"
                value={selected}
              />
              <Button
                disabled={!selected || addressPending}
                onClick={() => void assignAddress()}
                type="button"
              >
                {addressPending ? 'Updating address…' : 'Assign address'}
              </Button>
            </div>
          )}
          {error ? (
            <p className="text-sm text-red-700" role="alert">
              {error}
            </p>
          ) : null}
        </CardContent>
      ) : null}
    </Card>
  )
}

function ClientDetails({ client }: { client: VpnClientDetails }) {
  const renew = useRenewCertificate()
  const packageCertificate = usePackageCertificate()
  const revoke = useRevokeCertificate()
  const deleteClient = useDeleteClient()
  const navigate = useNavigate()
  const download = useCertificateDownload()
  const session = usePrincipalSession()
  const canWrite = hasPermission(session, 'clients:write')
  const [operationError, setOperationError] = useState<string | null>(null)
  const [operationPending, setOperationPending] = useState(false)
  const operationRef = useRef(false)

  async function operation(
    action: () => Promise<unknown>,
    message: string,
  ) {
    if (operationRef.current) {
      return
    }
    operationRef.current = true
    setOperationPending(true)
    setOperationError(null)
    try {
      await action()
      toast.success(message)
    } catch {
      setOperationError(
        message.replace(' completed.', ' could not be completed.'),
      )
    } finally {
      operationRef.current = false
      setOperationPending(false)
    }
  }

  async function deleteVpnClient() {
    await deleteClient.mutateAsync(client.name)
    toast.success('VPN client deleted.')
    navigate('/clients', { replace: true })
  }

  async function revokeCertificate() {
    if (operationRef.current) {
      throw new Error('A certificate operation is already running.')
    }
    operationRef.current = true
    setOperationPending(true)
    try {
      await revoke.mutateAsync(client.name)
      toast.success('Certificate revoked.')
    } finally {
      operationRef.current = false
      setOperationPending(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={client.name}
        description="VPN identity, virtual address, and certificate state."
        actions={
          <Button asChild variant="outline">
            <Link to="/clients">Back to VPN clients</Link>
          </Button>
        }
      />
      <Card>
        <CardContent className="pt-6">
          <dl className="grid gap-5 sm:grid-cols-2">
            <div>
              <dt className="text-sm text-muted-foreground">Certificate</dt>
              <dd className="mt-1">
                <CertificateStatus revoked={client.revoked} />
              </dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">Expires</dt>
              <dd>{certificateExpiryLabel(client.cert.expires_on)}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">Issued by</dt>
              <dd>{client.cert.issued_by}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted-foreground">Client network</dt>
              <dd>{client.cidr ?? 'None'}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>
      <ClientAddressCard canWrite={canWrite} client={client} />
      {canWrite && !client.revoked ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Certificate operations</h2>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-3">
            <Button
              disabled={operationPending}
              onClick={() =>
                void operation(
                  () => renew.mutateAsync(client.name),
                  'Certificate renewal completed.',
                )
              }
              type="button"
            >
              Renew
            </Button>
            <Button
              disabled={operationPending}
              onClick={() =>
                void operation(
                  () => packageCertificate.mutateAsync(client.name),
                  'Certificate packaging completed.',
                )
              }
              type="button"
              variant="outline"
            >
              Package
            </Button>
            <Button
              disabled={operationPending}
              onClick={() =>
                void operation(
                  () => download(client.name),
                  'Certificate download completed.',
                )
              }
              type="button"
              variant="outline"
            >
              Download
            </Button>
            <RevokeCertificateDialog
              clientName={client.name}
              disabled={operationPending}
              onRevoke={revokeCertificate}
            />
          </CardContent>
          {operationError ? (
            <p
              className="px-6 pb-6 text-sm text-red-700"
              role="alert"
            >
              {operationError ===
                'Certificate renewal could not be completed.'
                ? 'The certificate could not be renewed. Try again.'
                : 'The certificate operation could not be completed. ' +
                  'Try again.'}
            </p>
          ) : null}
        </Card>
      ) : null}
      {canWrite && client.revoked ? (
        <Card>
          <CardHeader>
            <h2 className="text-lg font-semibold">Delete VPN client</h2>
            <p className="text-sm text-muted-foreground">
              Delete this revoked client and its credentials. Linked edge
              devices are retained and detached.
            </p>
          </CardHeader>
          <CardContent>
            <DeleteClientDialog
              clientName={client.name}
              onDelete={deleteVpnClient}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

export function ClientDetailPage() {
  const { clientName: value } = useParams()
  let clientName = ''
  try {
    clientName = decodeURIComponent(value ?? '')
  } catch {
    clientName = ''
  }
  const query = useClientDetails(clientName, Boolean(clientName))
  if (!clientName || isMissing(query.error)) {
    return <MissingClient />
  }
  if (query.isPending) {
    return <LoadingTable columns={2} label="Loading VPN client details" />
  }
  if (query.data === undefined) {
    return <LoadFailure onRetry={() => void query.refetch()} />
  }
  return <ClientDetails client={query.data} />
}
