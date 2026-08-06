import type { ComponentProps } from 'react'

import { cn } from '@/lib/utils'

function Input({ className, type, ...props }: ComponentProps<'input'>) {
  return (
    <input
      className={cn(
        'flex h-10 w-full rounded-md border border-input bg-background',
        'px-3 py-2 text-sm outline-none placeholder:text-muted-foreground',
        'focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50',
        'aria-invalid:border-red-600',
        className,
      )}
      type={type}
      {...props}
    />
  )
}

export { Input }
