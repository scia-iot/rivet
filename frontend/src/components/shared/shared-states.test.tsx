import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { CopyButton } from '@/components/shared/copy-button'
import { EmptyState } from '@/components/shared/empty-state'
import { LoadingTable } from '@/components/shared/loading-table'
import { PageHeader } from '@/components/shared/page-header'
import { ProblemAlert } from '@/components/shared/problem-alert'
import { StatusBadge } from '@/components/shared/status-badge'

describe('shared page states', () => {
  it('supports keyboard page actions', async () => {
    const user = userEvent.setup()
    const onAction = vi.fn()

    render(
      <PageHeader
        title="Users"
        description="Manage control-panel users."
        actions={<button onClick={onAction}>Add user</button>}
      />,
    )

    expect(
      screen.getByRole('heading', { name: 'Users', level: 1 }),
    ).toBeVisible()
    await user.tab()
    expect(screen.getByRole('button', { name: 'Add user' })).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(onAction).toHaveBeenCalledOnce()
  })

  it('renders problem text literally and supports recovery', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    const detail = '<img src=x onerror=alert(1)>'
    const { container } = render(
      <ProblemAlert
        problem={{
          type: '/errors/example',
          title: 'Request failed',
          status: 500,
          detail,
        }}
        onRetry={onRetry}
      />,
    )

    expect(screen.getByRole('alert')).toHaveTextContent('Request failed')
    expect(screen.getByText(detail)).toBeVisible()
    expect(container.querySelector('img')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('uses a non-disruptive status when stale data remains visible', () => {
    render(
      <ProblemAlert
        stale
        problem={{
          type: '/errors/unavailable',
          title: 'Refresh failed',
          status: 503,
          detail: 'Showing the most recently loaded data.',
        }}
      />,
    )

    expect(screen.getByRole('status')).toHaveAccessibleName('Refresh failed')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('provides a named empty state and optional action', async () => {
    const user = userEvent.setup()
    const onAction = vi.fn()
    render(
      <EmptyState
        title="No users"
        description="Add the first user to get started."
        action={<button onClick={onAction}>Add user</button>}
      />,
    )

    expect(screen.getByRole('status', { name: 'No users' })).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Add user' }))
    expect(onAction).toHaveBeenCalledOnce()
  })

  it('preserves loading-table assistive semantics', () => {
    render(<LoadingTable columns={3} rows={2} label="Loading users" />)

    expect(screen.getByRole('status', { name: 'Loading users' })).toBeVisible()
    const table = screen.getByRole('table', { name: 'Loading users' })
    expect(table).toHaveAttribute('aria-busy', 'true')
    expect(screen.getAllByRole('row')).toHaveLength(3)
    expect(screen.getAllByRole('columnheader')).toHaveLength(3)
    expect(screen.getAllByRole('cell')).toHaveLength(6)
  })

  it('renders domain-neutral status tones with visible text', () => {
    const { rerender } = render(<StatusBadge label="Active" tone="positive" />)
    expect(screen.getByText('Active')).toBeVisible()

    rerender(<StatusBadge label="Pending" tone="warning" />)
    expect(screen.getByText('Pending')).toBeVisible()

    rerender(<StatusBadge label="Failed" tone="negative" />)
    expect(screen.getByText('Failed')).toBeVisible()
  })

  it('copies from the keyboard and announces success', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn<() => Promise<void>>().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    render(<CopyButton value="route-value" label="Copy route" />)

    await user.tab()
    expect(screen.getByRole('button', { name: 'Copy route' })).toHaveFocus()
    await user.keyboard('{Enter}')

    expect(writeText).toHaveBeenCalledWith('route-value')
    expect(await screen.findByRole('status')).toHaveTextContent('Copied')
  })

  it('reports clipboard denial without exception details', async () => {
    const user = userEvent.setup()
    const writeText = vi
      .fn<() => Promise<void>>()
      .mockRejectedValue(new Error('clipboard-secret'))
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    render(<CopyButton value="route-value" label="Copy route" />)

    await user.click(screen.getByRole('button', { name: 'Copy route' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Copy failed')
    expect(screen.queryByText(/clipboard-secret/)).not.toBeInTheDocument()
  })
})
