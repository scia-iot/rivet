import { Command as CommandPrimitive } from 'cmdk'
import { Search } from 'lucide-react'
import type { ComponentProps } from 'react'

import { cn } from '@/lib/utils'

function Command({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive>) {
  return (
    <CommandPrimitive
      className={cn('flex size-full flex-col overflow-hidden', className)}
      {...props}
    />
  )
}

function CommandInput({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive.Input>) {
  return (
    <div className="flex items-center gap-2 border-b px-3">
      <Search aria-hidden="true" className="size-4 shrink-0 opacity-50" />
      <CommandPrimitive.Input
        className={cn(
          'h-11 w-full bg-transparent text-sm outline-none',
          'placeholder:text-muted-foreground',
          className,
        )}
        {...props}
      />
    </div>
  )
}

function CommandList({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive.List>) {
  return (
    <CommandPrimitive.List
      className={cn('max-h-72 overflow-y-auto p-1', className)}
      {...props}
    />
  )
}

function CommandEmpty({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive.Empty>) {
  return (
    <CommandPrimitive.Empty
      className={cn('py-6 text-center text-sm', className)}
      {...props}
    />
  )
}

function CommandGroup({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive.Group>) {
  return (
    <CommandPrimitive.Group
      className={cn('overflow-hidden p-1', className)}
      {...props}
    />
  )
}

function CommandItem({
  className,
  ...props
}: ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      className={cn(
        'relative flex cursor-default select-none items-center',
        'rounded-sm px-2 py-2 text-sm outline-none',
        'data-[selected=true]:bg-accent data-[disabled=true]:opacity-50',
        className,
      )}
      {...props}
    />
  )
}

export {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
}
