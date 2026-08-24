import { lazy, Suspense } from 'react'
import { Route, Routes, useLocation } from 'react-router'

import { RouteErrorBoundary } from '@/app/error-boundary'
import { RequirePermission } from '@/auth/principal-session'
import { AppShell } from '@/components/app-shell'
import { PlaceholderPage } from '@/pages/placeholder-page'

const OVERVIEW_DESCRIPTION =
  'Monitor and administer this OpenVPN control plane.'

const loadDevicePages = () => import('@/features/devices/device-pages')
const loadUserPages = () => import('@/features/users/user-pages')
const loadClientPages = () => import('@/features/clients/client-pages')
const DeviceListPage = lazy(async () => ({
  default: (await loadDevicePages()).DeviceListPage,
}))
const CreateDevicePage = lazy(async () => ({
  default: (await loadDevicePages()).CreateDevicePage,
}))
const DeviceDetailPage = lazy(async () => ({
  default: (await loadDevicePages()).DeviceDetailPage,
}))
const EditDevicePage = lazy(async () => ({
  default: (await loadDevicePages()).EditDevicePage,
}))
const UserListPage = lazy(async () => ({
  default: (await loadUserPages()).UserListPage,
}))
const CreateUserPage = lazy(async () => ({
  default: (await loadUserPages()).CreateUserPage,
}))
const UserDetailPage = lazy(async () => ({
  default: (await loadUserPages()).UserDetailPage,
}))
const EditUserPage = lazy(async () => ({
  default: (await loadUserPages()).EditUserPage,
}))
const ClientListPage = lazy(async () => ({
  default: (await loadClientPages()).ClientListPage,
}))
const ClientDetailPage = lazy(async () => ({
  default: (await loadClientPages()).ClientDetailPage,
}))

function RouteLoading() {
  return (
    <main aria-busy="true" className="grid min-h-[60vh] place-items-center p-6">
      <p role="status">Loading page...</p>
    </main>
  )
}

export default function App() {
  const location = useLocation()

  return (
    <RouteErrorBoundary key={location.key}>
      <Suspense fallback={<RouteLoading />}>
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
                  <UserListPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/new"
              element={
                <RequirePermission permission="users:write">
                  <CreateUserPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/:userId"
              element={
                <RequirePermission permission="users:read">
                  <UserDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/:userId/edit"
              element={
                <RequirePermission permission="users:write">
                  <EditUserPage />
                </RequirePermission>
              }
            />
            <Route
              path="clients"
              element={
                <RequirePermission permission="clients:read">
                  <ClientListPage />
                </RequirePermission>
              }
            />
            <Route
              path="clients/:clientName"
              element={
                <RequirePermission permission="clients:read">
                  <ClientDetailPage />
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
      </Suspense>
    </RouteErrorBoundary>
  )
}
