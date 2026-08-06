import type { ComponentProps } from 'react'

import { cn } from '@/lib/utils'

function Textarea({ className, ...props }: ComponentProps<'textarea'>) {
  return (
    <textarea
      className={cn(
        'flex min-h-20 w-full rounded-md border border-input bg-background',
        'px-3 py-2 text-sm outline-none placeholder:text-muted-foreground',
        'focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50',
        'aria-invalid:border-red-600',
        className,
      )}
      {...props}
    />
  )
}

export { Textarea }
