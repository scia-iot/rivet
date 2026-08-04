import { QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { createQueryClient } from '@/app/query-client'
import { AuthenticationProvider } from '@/auth/authentication-provider'

const queryClient = createQueryClient()

export function ApplicationProviders({ children }: { children: ReactNode }) {
  return (
    <AuthenticationProvider>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </AuthenticationProvider>
  )
}
