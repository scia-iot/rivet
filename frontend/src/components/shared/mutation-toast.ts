import { toast } from 'sonner'

interface MutationToastMessages {
  success: string
  error: string
}

export async function runWithMutationToast<T>(
  mutation: () => Promise<T>,
  messages: MutationToastMessages,
): Promise<T> {
  try {
    const result = await mutation()
    toast.success(messages.success)
    return result
  } catch (error: unknown) {
    toast.error(messages.error)
    throw error
  }
}
