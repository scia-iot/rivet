import { Check, Copy } from 'lucide-react'
import { useState } from 'react'

import { Button } from '@/components/ui/button'

interface CopyButtonProps {
  value: string
  label?: string
}

export function CopyButton({ value, label = 'Copy' }: CopyButtonProps) {
  const [result, setResult] = useState<'idle' | 'copied' | 'failed'>('idle')

  async function copyValue() {
    try {
      await navigator.clipboard.writeText(value)
      setResult('copied')
    } catch {
      setResult('failed')
    }
  }

  const message = result === 'copied' ? 'Copied' : 'Copy failed'

  return (
    <>
      <Button
        aria-label={label}
        onClick={() => void copyValue()}
        size="icon"
        type="button"
        variant="ghost"
      >
        {result === 'copied' ? (
          <Check aria-hidden="true" />
        ) : (
          <Copy aria-hidden="true" />
        )}
      </Button>
      <span
        aria-live={result === 'failed' ? 'assertive' : 'polite'}
        className="sr-only"
        role={result === 'failed' ? 'alert' : 'status'}
      >
        {result === 'idle' ? '' : message}
      </span>
    </>
  )
}
