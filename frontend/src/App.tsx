import { Route, Routes, useLocation } from 'react-router'

import { RouteErrorBoundary } from '@/app/error-boundary'
import { RequirePermission } from '@/auth/principal-session'
import { AppShell } from '@/components/app-shell'
import {
  CreateDevicePage,
  DeviceDetailPage,
  DeviceListPage,
  EditDevicePage,
} from '@/features/devices/device-pages'
import { PlaceholderPage } from '@/pages/placeholder-page'

const OVERVIEW_DESCRIPTION =
  'Monitor and administer this OpenVPN control plane.'
const CLIENTS_DESCRIPTION =
  'Provision and maintain OpenVPN client identities.'

export default function App() {
  const location = useLocation()

  return (
    <RouteErrorBoundary key={location.key}>
      <Routes location={location}>
        <Route element={<AppShell />}>
          <Route
            index
            element={
              <RequirePermission permission="server:read">
                <PlaceholderPage
                  title="Overview"
                  description={OVERVIEW_DESCRIPTION}
                />
              </RequirePermission>
            }
          />
          <Route
            element={
              <RequirePermission permission="devices:read">
                <DeviceListPage />
              </RequirePermission>
            }
            path="devices"
          />
          <Route
            element={
              <RequirePermission permission="devices:write">
                <CreateDevicePage />
              </RequirePermission>
            }
            path="devices/new"
          />
          <Route
            element={
              <RequirePermission permission="devices:read">
                <DeviceDetailPage />
              </RequirePermission>
            }
            path="devices/:deviceId"
          />
          <Route
            element={
              <RequirePermission permission="devices:write">
                <EditDevicePage />
              </RequirePermission>
            }
            path="devices/:deviceId/edit"
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
                  description={CLIENTS_DESCRIPTION}
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
    </RouteErrorBoundary>
  )
}
