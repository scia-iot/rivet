import { zodResolver } from '@hookform/resolvers/zod'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useForm } from 'react-hook-form'
import { describe, expect, it, vi } from 'vitest'
import { z } from 'zod'

import { useLockedSubmit } from '@/components/shared/use-locked-submit'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'

const formSchema = z.object({
  name: z.string().min(3, 'Name must contain at least 3 characters.'),
})

type FormValues = z.infer<typeof formSchema>

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise
  })
  return { promise, resolve }
}

function ExampleForm({
  onSave,
}: {
  onSave: (values: FormValues) => Promise<void>
}) {
  const {
    formState: { errors },
    handleSubmit,
    register,
  } = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { name: '' },
  })
  const submission = useLockedSubmit(onSave)
  const errorId = errors.name ? 'name-error' : undefined

  return (
    <form aria-label="Example form" onSubmit={handleSubmit(submission.submit)}>
      <Field data-invalid={errors.name ? true : undefined}>
        <FieldLabel htmlFor="name">Name</FieldLabel>
        <Input
          {...register('name')}
          aria-describedby={errorId ?? 'name-description'}
          aria-invalid={errors.name ? true : undefined}
          id="name"
          minLength={3}
          required
        />
        <FieldDescription id="name-description">
          Use at least three characters.
        </FieldDescription>
        <FieldError id="name-error" errors={[errors.name]} />
      </Field>
      <Button disabled={submission.pending} type="submit">
        {submission.pending ? 'Saving…' : 'Save'}
      </Button>
    </form>
  )
}

describe('shared form patterns', () => {
  it('associates Zod errors with browser-constrained fields', async () => {
    render(<ExampleForm onSave={() => Promise.resolve()} />)
    const input = screen.getByRole('textbox', { name: 'Name' })

    expect(input).toBeRequired()
    expect(input).toHaveAttribute('minlength', '3')
    fireEvent.submit(screen.getByRole('form', { name: 'Example form' }))

    const error = await screen.findByRole('alert')
    expect(error).toHaveTextContent('Name must contain at least 3 characters.')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAccessibleDescription(
      'Name must contain at least 3 characters.',
    )
  })

  it('locks duplicate async form submissions', async () => {
    const user = userEvent.setup()
    const deferred = createDeferred<void>()
    const onSave = vi.fn(() => deferred.promise)
    render(<ExampleForm onSave={onSave} />)

    await user.type(screen.getByRole('textbox', { name: 'Name' }), 'Alice')
    const form = screen.getByRole('form', { name: 'Example form' })
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => expect(onSave).toHaveBeenCalledOnce())
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled()

    deferred.resolve()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
    })
  })

  it('provides named keyboard select and textarea primitives', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()
    render(
      <>
        <Field>
          <FieldLabel htmlFor="role">Role</FieldLabel>
          <Select onValueChange={onValueChange}>
            <SelectTrigger aria-label="Role" id="role">
              <SelectValue placeholder="Select a role" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="reader">Reader</SelectItem>
              <SelectItem value="admin">Administrator</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="notes">Notes</FieldLabel>
          <Textarea id="notes" />
        </Field>
      </>,
    )

    await user.tab()
    const trigger = screen.getByRole('combobox', { name: 'Role' })
    expect(trigger).toHaveFocus()
    await user.keyboard('{Enter}')
    await user.click(screen.getByRole('option', { name: 'Administrator' }))

    expect(onValueChange).toHaveBeenCalledWith('admin')
    expect(screen.getByRole('textbox', { name: 'Notes' })).toBeVisible()
  })
})
