import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface LoadingTableProps {
  columns: number
  rows?: number
  label?: string
}

export function LoadingTable({
  columns,
  rows = 5,
  label = 'Loading records',
}: LoadingTableProps) {
  const columnIndexes = Array.from({ length: columns }, (_, index) => index)
  const rowIndexes = Array.from({ length: rows }, (_, index) => index)

  return (
    <div className="rounded-md border">
      <p
        aria-label={label}
        aria-live="polite"
        className="sr-only"
        role="status"
      >
        {label}
      </p>
      <Table aria-busy="true" aria-label={label}>
        <TableHeader>
          <TableRow>
            {columnIndexes.map((column) => (
              <TableHead key={column}>
                <span className="sr-only">Column {column + 1}</span>
                <Skeleton className="h-4 w-20" />
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rowIndexes.map((row) => (
            <TableRow key={row}>
              {columnIndexes.map((column) => (
                <TableCell key={column}>
                  <Skeleton className="h-4 w-full" />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
