import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { runWithMutationToast } from '@/components/shared/mutation-toast'
import { Toaster } from '@/components/ui/sonner'

describe('mutation toasts', () => {
  it('announces a successful completed mutation', async () => {
    render(<Toaster />)

    await expect(
      runWithMutationToast(() => Promise.resolve('saved'), {
        success: 'Record saved.',
        error: 'Record could not be saved.',
      }),
    ).resolves.toBe('saved')

    expect(await screen.findByText('Record saved.')).toBeVisible()
  })

  it('uses a safe error toast and rethrows the failure', async () => {
    render(<Toaster />)
    const secretBearingError = new Error('token=do-not-render')

    await expect(
      runWithMutationToast(() => Promise.reject(secretBearingError), {
        success: 'Record saved.',
        error: 'Record could not be saved. Try again.',
      }),
    ).rejects.toBe(secretBearingError)

    expect(
      await screen.findByText('Record could not be saved. Try again.'),
    ).toBeVisible()
    expect(screen.queryByText(/do-not-render/)).not.toBeInTheDocument()
  })
})
