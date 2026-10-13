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

interface DeleteClientDialogProps {
  clientName: string
  onDelete: () => Promise<void>
}

export function DeleteClientDialog({
  clientName,
  onDelete,
}: DeleteClientDialogProps) {
  const [open, setOpen] = useState(false)
  const [confirmation, setConfirmation] = useState('')
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  const pendingRef = useRef(false)

  function changeOpen(next: boolean) {
    if (pendingRef.current && !next) return
    setOpen(next)
    if (next) {
      setConfirmation('')
      setFailed(false)
    }
  }

  async function remove() {
    if (pendingRef.current || confirmation !== clientName) return
    pendingRef.current = true
    setPending(true)
    setFailed(false)
    try {
      await onDelete()
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
        <Button type="button" variant="destructive">Delete VPN client</Button>
      </DialogTrigger>
      <DialogContent showCloseButton={!pending}>
        <DialogHeader>
          <DialogTitle>Delete {clientName}?</DialogTitle>
          <DialogDescription>
            This removes the revoked VPN client and its local credentials.
            Linked edge devices are retained. Type the exact client name to
            continue.
          </DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor="delete-client-name">Client name</FieldLabel>
          <Input
            autoComplete="off"
            disabled={pending}
            id="delete-client-name"
            onChange={(event) => setConfirmation(event.target.value)}
            value={confirmation}
          />
        </Field>
        {failed ? (
          <p className="text-sm text-red-700" role="alert">
            The VPN client could not be deleted. Try again.
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
            onClick={() => void remove()}
            type="button"
            variant="destructive"
          >
            {pending ? 'Deleting…' : 'Delete VPN client'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
