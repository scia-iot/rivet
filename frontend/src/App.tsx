import { Route, Routes } from 'react-router'

import { AppShell } from '@/components/app-shell'
import { PlaceholderPage } from '@/pages/placeholder-page'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route
          index
          element={
            <PlaceholderPage
              title="Overview"
              description="Monitor and administer this OpenVPN control plane."
            />
          }
        />
        <Route
          path="devices"
          element={
            <PlaceholderPage
              title="Devices"
              description="Manage stable edge-device identities."
            />
          }
        />
        <Route
          path="users"
          element={
            <PlaceholderPage
              title="Users"
              description="Manage OAuth-backed users and their VPN clients."
            />
          }
        />
        <Route
          path="clients"
          element={
            <PlaceholderPage
              title="VPN clients"
              description="Provision and maintain OpenVPN client identities."
            />
          }
        />
        <Route
          path="access"
          element={
            <PlaceholderPage
              title="Access"
              description="Review individual user-to-device access grants."
            />
          }
        />
        <Route
          path="*"
          element={
            <PlaceholderPage
              title="Page not found"
              description="The requested control-panel page does not exist."
            />
          }
        />
      </Route>
    </Routes>
  )
}
