import { zodResolver } from '@hookform/resolvers/zod'
import { Controller, useForm } from 'react-hook-form'
import { z } from 'zod'

import { ApiProblemError } from '@/api/problem-details'
import { EntitySelect } from '@/components/shared/entity-select'
import { useLockedSubmit } from '@/components/shared/use-locked-submit'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import type {
  DeviceCreate,
  VpnClient,
} from '@/features/devices/device-api'

const deviceFormSchema = z.object({
  clientId: z.string(),
  name: z
    .string()
    .trim()
    .min(1, 'Enter a device name.')
    .max(255, 'Device names cannot exceed 255 characters.'),
})

type DeviceFormValues = z.infer<typeof deviceFormSchema>

interface DeviceFormProps {
  clients: VpnClient[]
  initialClientId?: number | null
  initialName?: string
  onSave: (request: DeviceCreate) => Promise<void>
  submitLabel: string
  pendingLabel: string
}

function clientLabel(client: VpnClient): string {
  return client.revoked ? `${client.name} (revoked)` : client.name
}

export function DeviceForm({
  clients,
  initialClientId,
  initialName = '',
  onSave,
  submitLabel,
  pendingLabel,
}: DeviceFormProps) {
  const {
    clearErrors,
    control,
    formState: { errors },
    handleSubmit,
    register,
    setError,
  } = useForm<DeviceFormValues>({
    defaultValues: {
      clientId: initialClientId?.toString() ?? '',
      name: initialName,
    },
    resolver: zodResolver(deviceFormSchema),
  })

  async function save(values: DeviceFormValues) {
    clearErrors()
    try {
      await onSave({
        client_id: values.clientId ? Number(values.clientId) : null,
        name: values.name.trim(),
      })
    } catch (error: unknown) {
      if (error instanceof ApiProblemError) {
        const detail = error.problem.detail ?? ''
        if (error.problem.status === 404 && detail.startsWith('Client')) {
          setError('clientId', {
            message: 'The selected VPN client no longer exists.',
          })
          return
        }
        if (error.problem.status === 409 && detail.startsWith('Client')) {
          setError('clientId', {
            message: [
              'The selected VPN client is already assigned to another',
              'device.',
            ].join(' '),
          })
          return
        }
        if (error.problem.status === 409) {
          setError('name', {
            message: 'A device with this name already exists.',
          })
          return
        }
        if (error.problem.status === 404) {
          setError('root.server', {
            message: 'This device no longer exists.',
          })
          return
        }
      }
      setError('root.server', {
        message: 'The device could not be saved. Try again.',
      })
    }
  }

  const submission = useLockedSubmit(save)
  const nameErrorId = errors.name ? 'device-name-error' : undefined
  const clientErrorId = errors.clientId ? 'device-client-error' : undefined

  return (
    <form
      aria-label="Device form"
      className="grid max-w-2xl gap-6"
      onSubmit={handleSubmit(submission.submit)}
    >
      <Field data-invalid={errors.name ? true : undefined}>
        <FieldLabel htmlFor="device-name">Device name</FieldLabel>
        <Input
          {...register('name')}
          aria-describedby={nameErrorId ?? 'device-name-description'}
          aria-invalid={errors.name ? true : undefined}
          autoComplete="off"
          id="device-name"
          maxLength={255}
          required
        />
        <FieldDescription id="device-name-description">
          Use a unique name that identifies the physical device.
        </FieldDescription>
        <FieldError id="device-name-error" errors={[errors.name]} />
      </Field>

      <Controller
        control={control}
        name="clientId"
        render={({ field }) => (
          <Field data-invalid={errors.clientId ? true : undefined}>
            <FieldLabel htmlFor="device-client">
              Current VPN client
            </FieldLabel>
            <EntitySelect
              id="device-client"
              aria-describedby={
                clientErrorId ?? 'device-client-description'
              }
              aria-invalid={errors.clientId ? true : undefined}
              emptyText="No eligible VPN clients found."
              label="Current VPN client"
              onValueChange={field.onChange}
              options={[
                { value: '', label: 'No VPN client' },
                ...clients.flatMap((client) =>
                  client.id === undefined
                    ? []
                    : [
                        {
                          value: client.id.toString(),
                          label: clientLabel(client),
                          keywords: [client.name],
                        },
                      ],
                ),
              ]}
              placeholder="No VPN client"
              searchPlaceholder="Search VPN clients"
              value={field.value}
            />
            <FieldDescription id="device-client-description">
              A device can remain unlinked. Only clients not assigned to
              another device are available.
            </FieldDescription>
            <FieldError id="device-client-error" errors={[errors.clientId]} />
          </Field>
        )}
      />

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
