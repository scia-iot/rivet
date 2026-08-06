import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'

describe('remaining shared UI primitives', () => {
  it('activates a named dropdown item from the keyboard', async () => {
    const user = userEvent.setup()
    const onSelect = vi.fn()
    render(
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button>Account actions</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuItem onSelect={onSelect}>Sign out</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>,
    )

    await user.tab()
    await user.keyboard('{Enter}')
    const item = await screen.findByRole('menuitem', { name: 'Sign out' })
    expect(item).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(onSelect).toHaveBeenCalledOnce()
  })

  it('supports arrow-key tab activation and semantic separators', async () => {
    const user = userEvent.setup()
    render(
      <>
        <Tabs defaultValue="overview">
          <TabsList aria-label="Record sections">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
          </TabsList>
          <TabsContent value="overview">Overview content</TabsContent>
          <TabsContent value="history">History content</TabsContent>
        </Tabs>
        <Separator decorative={false} aria-label="Related content" />
      </>,
    )

    screen.getByRole('tab', { name: 'Overview' }).focus()
    await user.keyboard('{ArrowRight}')

    expect(screen.getByRole('tab', { name: 'History' })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(screen.getByText('History content')).toBeVisible()
    expect(
      screen.getByRole('separator', { name: 'Related content' }),
    ).toBeVisible()
  })

  it('shows named tooltip help when its trigger receives focus', async () => {
    const user = userEvent.setup()
    render(
      <TooltipProvider delayDuration={0}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button aria-label="Connection help">?</Button>
          </TooltipTrigger>
          <TooltipContent>Explains connection state</TooltipContent>
        </Tooltip>
      </TooltipProvider>,
    )

    await user.tab()
    expect(
      await screen.findByRole('tooltip', {
        name: 'Explains connection state',
      }),
    ).toBeVisible()
  })
})
