import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

type StatusTone = 'neutral' | 'positive' | 'warning' | 'negative'

const toneClasses: Record<StatusTone, string> = {
  neutral: '',
  positive: 'border-emerald-300 bg-emerald-50 text-emerald-800',
  warning: 'border-amber-300 bg-amber-50 text-amber-900',
  negative: 'border-red-300 bg-red-50 text-red-800',
}

interface StatusBadgeProps {
  label: string
  tone?: StatusTone
  className?: string
}

export function StatusBadge({
  label,
  tone = 'neutral',
  className,
}: StatusBadgeProps) {
  return (
    <Badge
      className={cn(toneClasses[tone], className)}
      variant={tone === 'neutral' ? 'secondary' : 'outline'}
    >
      {label}
    </Badge>
  )
}
