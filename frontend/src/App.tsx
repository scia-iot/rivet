import { Route, Routes } from 'react-router'

import { RequirePermission } from '@/auth/principal-session'
import { AppShell } from '@/components/app-shell'
import { PlaceholderPage } from '@/pages/placeholder-page'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route
          index
          element={
            <RequirePermission permission="server:read">
              <PlaceholderPage
                title="Overview"
                description="Monitor and administer this OpenVPN control plane."
              />
            </RequirePermission>
          }
        />
        <Route
          path="devices"
          element={
            <RequirePermission permission="devices:read">
              <PlaceholderPage
                title="Devices"
                description="Manage stable edge-device identities."
              />
            </RequirePermission>
          }
        />
        <Route
          path="users"
          element={
            <RequirePermission permission="users:read">
              <PlaceholderPage
                title="Users"
                description="Manage OAuth-backed users and their VPN clients."
              />
            </RequirePermission>
          }
        />
        <Route
          path="clients"
          element={
            <RequirePermission permission="clients:read">
              <PlaceholderPage
                title="VPN clients"
                description="Provision and maintain OpenVPN client identities."
              />
            </RequirePermission>
          }
        />
        <Route
          path="access"
          element={
            <RequirePermission permission="access:read">
              <PlaceholderPage
                title="Access"
                description="Review individual user-to-device access grants."
              />
            </RequirePermission>
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
