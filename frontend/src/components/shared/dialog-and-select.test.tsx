import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { ConfirmActionDialog } from '@/components/shared/confirm-action-dialog'
import { EntitySelect } from '@/components/shared/entity-select'
import { Field, FieldError, FieldLabel } from '@/components/ui/field'

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })

  return { promise, reject, resolve }
}

describe('ConfirmActionDialog', () => {
  it('moves focus into dialog and restores it on cancel', async () => {
    const user = userEvent.setup()
    render(
      <ConfirmActionDialog
        title="Delete record?"
        description="This operation cannot be undone."
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        trigger={<button>Delete record</button>}
        onConfirm={() => Promise.resolve()}
      />,
    )

    const trigger = screen.getByRole('button', { name: 'Delete record' })
    trigger.focus()
    await user.keyboard('{Enter}')

    const dialog = screen.getByRole('dialog', { name: 'Delete record?' })
    expect(dialog).toContainElement(document.activeElement as HTMLElement)

    await user.keyboard('{Escape}')
    expect(dialog).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('locks duplicate confirmation with its pending label', async () => {
    const user = userEvent.setup()
    const deferred = createDeferred<void>()
    const onConfirm = vi.fn(() => deferred.promise)
    render(
      <ConfirmActionDialog
        title="Delete record?"
        description="This operation cannot be undone."
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        trigger={<button>Delete record</button>}
        onConfirm={onConfirm}
      />,
    )

    const trigger = screen.getByRole('button', { name: 'Delete record' })
    await user.click(trigger)
    const confirm = screen.getByRole('button', { name: 'Delete' })
    fireEvent.click(confirm)
    fireEvent.click(confirm)

    expect(onConfirm).toHaveBeenCalledOnce()
    expect(screen.getByRole('button', { name: 'Deleting…' })).toBeDisabled()

    deferred.resolve()
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
    expect(trigger).toHaveFocus()
  })

  it('keeps rejected actions open and permits one locked retry', async () => {
    const user = userEvent.setup()
    const retry = createDeferred<void>()
    const onConfirm = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error('destructive-secret'))
      .mockImplementationOnce(() => retry.promise)
    render(
      <ConfirmActionDialog
        title="Delete record?"
        description="This operation cannot be undone."
        confirmLabel="Delete"
        pendingLabel="Deleting…"
        trigger={<button>Delete record</button>}
        onConfirm={onConfirm}
      />,
    )

    const trigger = screen.getByRole('button', { name: 'Delete record' })
    await user.click(trigger)
    await user.click(screen.getByRole('button', { name: 'Delete' }))

    const dialog = screen.getByRole('dialog', { name: 'Delete record?' })
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The action could not be completed. Try again.',
    )
    expect(screen.queryByText(/destructive-secret/)).not.toBeInTheDocument()
    expect(dialog).toContainElement(document.activeElement as HTMLElement)

    const retryButton = screen.getByRole('button', { name: 'Delete' })
    fireEvent.click(retryButton)
    fireEvent.click(retryButton)
    expect(onConfirm).toHaveBeenCalledTimes(2)

    retry.reject(new Error('retry-secret'))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled()
    })
    expect(screen.queryByText(/retry-secret/)).not.toBeInTheDocument()
    expect(dialog).toContainElement(document.activeElement as HTMLElement)

    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })
})

describe('EntitySelect', () => {
  it('supports keyboard opening, search, and selection', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()
    render(
      <EntitySelect
        label="User"
        placeholder="Select a user"
        searchPlaceholder="Search users"
        options={[
          { value: 'alice', label: 'Alice Adams' },
          { value: 'bob', label: 'Bob Brown' },
        ]}
        onValueChange={onValueChange}
      />,
    )

    await user.tab()
    const trigger = screen.getByRole('combobox', { name: 'User' })
    expect(trigger).toHaveFocus()
    await user.keyboard('{Enter}')

    const search = screen.getByRole('combobox', { name: 'Search users' })
    expect(search).toHaveFocus()
    await user.type(search, 'Bob')
    await user.click(screen.getByRole('option', { name: 'Bob Brown' }))

    expect(onValueChange).toHaveBeenCalledWith('bob')
    expect(trigger).toHaveTextContent('Bob Brown')
    expect(trigger).toHaveFocus()
  })

  it('announces an empty search result', async () => {
    const user = userEvent.setup()
    render(
      <EntitySelect
        label="User"
        options={[{ value: 'alice', label: 'Alice Adams' }]}
        onValueChange={() => undefined}
      />,
    )

    await user.click(screen.getByRole('combobox', { name: 'User' }))
    await user.type(
      screen.getByRole('combobox', { name: 'Search entities' }),
      'Nobody',
    )

    expect(screen.getByText('No results found.')).toBeVisible()
  })

  it('associates field errors and describes selection', async () => {
    const user = userEvent.setup()
    render(
      <Field data-invalid>
        <FieldLabel htmlFor="owner">Owner</FieldLabel>
        <EntitySelect
          id="owner"
          aria-describedby="owner-error"
          aria-invalid
          label="Owner"
          options={[
            { value: 'alice', label: 'Alice Adams' },
            { value: 'bob', label: 'Bob Brown' },
          ]}
          value="alice"
          onValueChange={() => undefined}
        />
        <FieldError id="owner-error">Choose an available owner.</FieldError>
      </Field>,
    )

    const trigger = screen.getByRole('combobox', { name: 'Owner' })
    expect(screen.getByText('Owner')).toHaveAttribute('for', 'owner')
    expect(trigger).toHaveAttribute('id', 'owner')
    expect(trigger).toHaveAttribute('aria-invalid', 'true')
    expect(trigger).toHaveAccessibleDescription('Choose an available owner.')
    expect(trigger).toHaveTextContent('Alice Adams')

    await user.click(trigger)
    expect(
      screen.getByRole('dialog', { name: 'Owner' }),
    ).toHaveAccessibleDescription(
      'Search and choose an option for Owner. Current selection: Alice Adams.',
    )
  })
})
