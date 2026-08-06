import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { RouteErrorBoundary } from '@/app/error-boundary'

const consoleError = vi
  .spyOn(console, 'error')
  .mockImplementation(() => undefined)

afterEach(() => {
  consoleError.mockClear()
})

describe('RouteErrorBoundary', () => {
  it('retries safely without rendering exception content', async () => {
    const user = userEvent.setup()
    let shouldThrow = true

    function TransientRoute() {
      if (shouldThrow) {
        throw new Error('<img src=x onerror=alert(1)> token=do-not-render')
      }
      return <h1>Recovered route</h1>
    }

    const { container } = render(
      <RouteErrorBoundary>
        <TransientRoute />
      </RouteErrorBoundary>,
    )

    expect(
      screen.getByRole('heading', { name: 'Something went wrong' }),
    ).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent(
      'The page encountered an unexpected error.',
    )
    expect(screen.queryByText(/do-not-render/)).not.toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()

    shouldThrow = false
    await user.click(screen.getByRole('button', { name: 'Try again' }))

    expect(
      screen.getByRole('heading', { name: 'Recovered route' }),
    ).toBeVisible()
  })
})
