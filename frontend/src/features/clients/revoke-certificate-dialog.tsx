import { useRef, useState } from 'react'

import { Button } from '@/components/ui/button'
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
import { Field, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'

interface RevokeCertificateDialogProps {
  clientName: string
  disabled?: boolean
  onRevoke: () => Promise<void>
}

export function RevokeCertificateDialog({
  clientName,
  disabled = false,
  onRevoke,
}: RevokeCertificateDialogProps) {
  const [open, setOpen] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  const pendingRef = useRef(false)

  function changeOpen(next: boolean) {
    if (pendingRef.current && !next) {
      return
    }
    setOpen(next)
    if (next) {
      setConfirmation('')
      setFailed(false)
    }
  }

  async function revoke() {
    if (pendingRef.current || confirmation !== clientName) {
      return
    }
    pendingRef.current = true
    setPending(true)
    setFailed(false)
    try {
      await onRevoke()
      setOpen(false)
    } catch {
      setFailed(true)
    } finally {
      pendingRef.current = false
      setPending(false)
    }
  }

  return (
    <Dialog onOpenChange={changeOpen} open={open}>
      <DialogTrigger asChild>
        <Button disabled={disabled} type="button" variant="destructive">
          Revoke certificate
        </Button>
      </DialogTrigger>
      <DialogContent showCloseButton={!pending}>
        <DialogHeader>
          <DialogTitle>Revoke {clientName}?</DialogTitle>
          <DialogDescription>
            Revocation is destructive. The certificate cannot be used again.
            Type the exact client name to continue.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor="revoke-client-name">Client name</FieldLabel>
          <Input
            autoComplete="off"
            disabled={pending}
            id="revoke-client-name"
            onChange={(event) => setConfirmation(event.target.value)}
            value={confirmation}
          />
        </Field>
        {failed ? (
          <p className="text-sm text-red-700" role="alert">
            The certificate could not be revoked. Try again.
          </p>
        ) : null}
        <DialogFooter>
          <DialogClose asChild>
            <Button disabled={pending} type="button" variant="outline">
              Cancel
            </Button>
          </DialogClose>
          <Button
            disabled={pending || confirmation !== clientName}
            onClick={() => void revoke()}
            type="button"
            variant="destructive"
          >
            {pending ? 'Revoking…' : 'Revoke certificate'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
