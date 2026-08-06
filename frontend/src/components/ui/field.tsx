import type { ComponentProps, ReactNode } from 'react'

import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

function Field({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn('grid gap-2 data-[invalid=true]:text-red-700', className)}
      {...props}
    />
  )
}

function FieldLabel({ className, ...props }: ComponentProps<typeof Label>) {
  return <Label className={cn('w-fit', className)} {...props} />
}

function FieldDescription({ className, ...props }: ComponentProps<'p'>) {
  return (
    <p className={cn('text-sm text-muted-foreground', className)} {...props} />
  )
}

interface FieldErrorProps extends ComponentProps<'p'> {
  errors?: Array<{ message?: unknown } | undefined>
  children?: ReactNode
}

function FieldError({
  className,
  errors,
  children,
  ...props
}: FieldErrorProps) {
  const messages = errors
    ?.map((error) => error?.message)
    .filter((message): message is string => typeof message === 'string')
  const content = children ?? messages?.join(', ')

  if (!content) {
    return null
  }

  return (
    <p
      className={cn('text-sm font-normal text-red-700', className)}
      role="alert"
      {...props}
    >
      {content}
    </p>
  )
}

export { Field, FieldDescription, FieldError, FieldLabel }
