import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import { z } from 'zod'

import { ApiProblemError } from '@/api/problem-details'
import { useLockedSubmit } from '@/components/shared/use-locked-submit'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import type { UserCreate } from '@/features/users/user-api'

const userFormSchema = z.object({
  displayName: z
    .string()
    .trim()
    .min(1, 'Enter a display name.')
    .max(255, 'Display names cannot exceed 255 characters.'),
  issuer: z
    .string()
    .trim()
    .min(1, 'Enter the validated token issuer.')
    .max(2048, 'Issuers cannot exceed 2048 characters.'),
  subject: z
    .string()
    .trim()
    .min(1, 'Enter the stable token subject.')
    .max(255, 'Subjects cannot exceed 255 characters.'),
})

type UserFormValues = z.infer<typeof userFormSchema>

interface UserFormProps {
  initialName?: string
  issuer?: string
  subject?: string
  identityEditable?: boolean
  onSave: (request: UserCreate) => Promise<void>
  pendingLabel: string
  submitLabel: string
}

export function UserForm({
  initialName = '',
  issuer = '',
  subject = '',
  identityEditable = false,
  onSave,
  pendingLabel,
  submitLabel,
}: UserFormProps) {
  const {
    clearErrors,
    formState: { errors },
    handleSubmit,
    register,
    setError,
  } = useForm<UserFormValues>({
    defaultValues: {
      displayName: initialName,
      issuer,
      subject,
    },
    resolver: zodResolver(userFormSchema),
  })

  async function save(values: UserFormValues) {
    clearErrors()
    try {
      await onSave({
        display_name: values.displayName.trim(),
        issuer: values.issuer.trim(),
        subject: values.subject.trim(),
      })
    } catch (error: unknown) {
      if (error instanceof ApiProblemError) {
        if (error.problem.status === 409) {
          setError('root.server', {
            message: 'This external identity is already registered.',
          })
          return
        }
        if (error.problem.status === 404) {
          setError('root.server', {
            message: 'This user no longer exists.',
          })
          return
        }
      }
      setError('root.server', {
        message: 'The user could not be saved. Try again.',
      })
    }
  }

  const submission = useLockedSubmit(save)

  return (
    <form
      aria-label="User form"
      className="grid max-w-2xl gap-6"
      onSubmit={handleSubmit(submission.submit)}
    >
      <Field data-invalid={errors.displayName ? true : undefined}>
        <FieldLabel htmlFor="user-display-name">Display name</FieldLabel>
        <Input
          {...register('displayName')}
          aria-describedby={
            errors.displayName ? 'user-display-name-error' : undefined
          }
          aria-invalid={errors.displayName ? true : undefined}
          autoComplete="off"
          id="user-display-name"
          maxLength={255}
          required
        />
        <FieldError
          id="user-display-name-error"
          errors={[errors.displayName]}
        />
      </Field>

      {identityEditable ? (
        <>
          <Field data-invalid={errors.issuer ? true : undefined}>
            <FieldLabel htmlFor="user-issuer">Issuer</FieldLabel>
            <Input
              {...register('issuer')}
              aria-describedby={
                errors.issuer
                  ? 'user-issuer-description user-issuer-error'
                  : 'user-issuer-description'
              }
              aria-invalid={errors.issuer ? true : undefined}
              autoComplete="off"
              id="user-issuer"
              maxLength={2048}
              required
            />
            <FieldDescription id="user-issuer-description">
              Enter the exact issuer from the validated identity token.
            </FieldDescription>
            <FieldError id="user-issuer-error" errors={[errors.issuer]} />
          </Field>
          <Field data-invalid={errors.subject ? true : undefined}>
            <FieldLabel htmlFor="user-subject">Subject</FieldLabel>
            <Input
              {...register('subject')}
              aria-describedby={
                errors.subject
                  ? 'user-subject-description user-subject-error'
                  : 'user-subject-description'
              }
              aria-invalid={errors.subject ? true : undefined}
              autoComplete="off"
              id="user-subject"
              maxLength={255}
              required
            />
            <FieldDescription id="user-subject-description">
              Enter the exact stable subject from the validated token.
            </FieldDescription>
            <FieldError id="user-subject-error" errors={[errors.subject]} />
          </Field>
        </>
      ) : (
        <>
          <input {...register('issuer')} type="hidden" />
          <input {...register('subject')} type="hidden" />
        </>
      )}

      {errors.root?.server ? (
        <FieldError>{errors.root.server.message}</FieldError>
      ) : null}
      <div className="flex justify-end">
        <Button disabled={submission.pending} type="submit">
          {submission.pending ? pendingLabel : submitLabel}
        </Button>
      </div>
    </form>
  )
}
