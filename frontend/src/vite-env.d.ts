/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string
  readonly VITE_AUTH_DISABLED?: string
  readonly VITE_ENTRA_API_SCOPE?: string
  readonly VITE_ENTRA_CLIENT_ID?: string
  readonly VITE_ENTRA_TENANT_ID?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
