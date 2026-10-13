import { useRef, useState, type ReactElement } from 'react'

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

interface ConfirmActionDialogProps {
  title: string
  description: string
  confirmLabel: string
  pendingLabel: string
  trigger: ReactElement
  onConfirm: () => Promise<void>
  onError?: (error: unknown) => void
}

export function ConfirmActionDialog({
  title,
  description,
  confirmLabel,
  pendingLabel,
  trigger,
  onConfirm,
  onError,
}: ConfirmActionDialogProps) {
  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState(false)
  const [failed, setFailed] = useState(false)
  const pendingRef = useRef(false)

  function changeOpen(nextOpen: boolean) {
    if (pendingRef.current && !nextOpen) {
      return
    }
    setOpen(nextOpen)
    if (nextOpen) {
      setFailed(false)
    }
  }

  async function confirm() {
    if (pendingRef.current) {
      return
    }

    pendingRef.current = true
    setPending(true)
    setFailed(false)
    try {
      await onConfirm()
      pendingRef.current = false
      setPending(false)
      setOpen(false)
    } catch (error: unknown) {
      pendingRef.current = false
      setPending(false)
      setFailed(true)
      onError?.(error)
    }
  }

  return (
    <Dialog onOpenChange={changeOpen} open={open}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent showCloseButton={!pending}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        {failed ? (
          <p className="text-sm text-red-700" role="alert">
            The action could not be completed. Try again.
          </p>
        ) : null}
        <DialogFooter>
          <DialogClose asChild>
            <Button disabled={pending} type="button" variant="outline">
              Cancel
            </Button>
          </DialogClose>
          <Button
            disabled={pending}
            onClick={() => void confirm()}
            type="button"
            variant="destructive"
          >
            {pending ? pendingLabel : confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
