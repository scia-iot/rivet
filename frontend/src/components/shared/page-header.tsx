import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <header
      className={cn(
        'flex flex-col gap-4',
        'sm:flex-row sm:items-start sm:justify-between',
      )}
    >
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
        {description ? (
          <p className="mt-2 text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </header>
  )
}
