import { useId } from 'react'

import type { ProblemDetails } from '@/api/problem-details'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

interface ProblemAlertProps {
  problem: ProblemDetails
  onRetry?: () => void
  stale?: boolean
}

export function ProblemAlert({ problem, onRetry, stale }: ProblemAlertProps) {
  const titleId = useId()

  return (
    <Alert
      aria-labelledby={titleId}
      className={stale ? 'border-amber-300' : 'border-red-300'}
      role={stale ? 'status' : 'alert'}
    >
      <AlertTitle id={titleId}>{problem.title}</AlertTitle>
      <AlertDescription>
        {problem.detail ? <p>{problem.detail}</p> : null}
        {problem.status === 403 ? (
          <p className="mt-1">Ask an administrator if you need access.</p>
        ) : null}
        {onRetry ? (
          <Button
            className="mt-3"
            onClick={onRetry}
            size="sm"
            variant="outline"
          >
            Try again
          </Button>
        ) : null}
      </AlertDescription>
    </Alert>
  )
}
