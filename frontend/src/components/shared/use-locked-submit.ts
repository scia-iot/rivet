import { useRef, useState } from 'react'

export function useLockedSubmit<T>(onSubmit: (value: T) => Promise<void>): {
  pending: boolean
  submit: (value: T) => Promise<void>
} {
  const pendingRef = useRef(false)
  const [pending, setPending] = useState(false)

  async function submit(value: T) {
    if (pendingRef.current) {
      return
    }

    pendingRef.current = true
    setPending(true)
    try {
      await onSubmit(value)
    } finally {
      pendingRef.current = false
      setPending(false)
    }
  }

  return { pending, submit }
}
