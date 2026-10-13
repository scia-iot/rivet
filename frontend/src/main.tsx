import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'

import App from '@/App'
import { ApplicationProviders } from '@/app/providers'
import '@/index.css'

const root = document.getElementById('root')
if (root === null) {
  throw new Error('Frontend root element not found.')
}

createRoot(root).render(
  <StrictMode>
    <ApplicationProviders>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ApplicationProviders>
  </StrictMode>,
)
