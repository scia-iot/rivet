import type { ComponentProps } from 'react'

import { cn } from '@/lib/utils'

function Alert({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn(
        'relative w-full rounded-lg border bg-background px-4 py-3 text-sm',
        className,
      )}
      {...props}
    />
  )
}

function AlertTitle({ className, ...props }: ComponentProps<'h2'>) {
  return (
    <h2 className={cn('mb-1 font-medium leading-none', className)} {...props} />
  )
}

function AlertDescription({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn('text-sm text-muted-foreground', className)}
      {...props}
    />
  )
}

export { Alert, AlertDescription, AlertTitle }
