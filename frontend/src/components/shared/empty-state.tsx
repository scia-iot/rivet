import { useId, type ReactNode } from 'react'

interface EmptyStateProps {
  title: string
  description: string
  action?: ReactNode
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  const titleId = useId()

  return (
    <section
      aria-labelledby={titleId}
      className="rounded-lg border border-dashed px-6 py-12 text-center"
      role="status"
    >
      <h2 className="text-lg font-semibold" id={titleId}>
        {title}
      </h2>
      <p className="mt-2 text-sm text-muted-foreground">{description}</p>
      {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
    </section>
  )
}
