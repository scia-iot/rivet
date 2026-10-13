import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { ApplicationProviders } from '@/app/providers'
import { Button } from '@/components/ui/button'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

vi.mock('@/auth/authentication-provider', () => ({
  AuthenticationProvider: ({ children }: { children: ReactNode }) => children,
}))

vi.mock('@/auth/authentication-gate', () => ({
  AuthenticationGate: ({ children }: { children: ReactNode }) => children,
}))

describe('ApplicationProviders', () => {
  it('provides tooltips globally without feature-level setup', async () => {
    const user = userEvent.setup()
    render(
      <ApplicationProviders>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button aria-label="Global help">?</Button>
          </TooltipTrigger>
          <TooltipContent>Available from application providers</TooltipContent>
        </Tooltip>
      </ApplicationProviders>,
    )

    await user.tab()
    expect(
      await screen.findByRole('tooltip', {
        name: 'Available from application providers',
      }),
    ).toBeVisible()
  })
})
