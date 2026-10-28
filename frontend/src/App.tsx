import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router'

import { RouteErrorBoundary } from '@/app/error-boundary'
import { routePermissions } from '@/auth/permissions'
import { RequirePermission } from '@/auth/principal-session'
import {
  hasPermission,
  usePrincipalSession,
} from '@/auth/use-principal-session'
import { AppShell } from '@/components/app-shell'
import { PlaceholderPage } from '@/pages/placeholder-page'

const loadDevicePages = () => import('@/features/devices/device-pages')
const loadUserPages = () => import('@/features/users/user-pages')
const loadClientPages = () => import('@/features/clients/client-pages')
const loadServerPages = () => import('@/features/server/server-pages')
const loadNetworkPages = () => import('@/features/networks/network-pages')
const loadPortalNetworkPages = () => import('@/features/portal/portal-network-pages')
const loadPortalPages = () => import('@/features/portal/portal-pages')
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
const ServerPage = lazy(async () => ({
  default: (await loadServerPages()).ServerPage,
}))
const ServerRoutesPage = lazy(async () => ({
  default: (await loadServerPages()).ServerRoutesPage,
}))
const NetworkListPage = lazy(async () => ({
  default: (await loadNetworkPages()).NetworkListPage,
}))
const NetworkDetailPage = lazy(async () => ({
  default: (await loadNetworkPages()).NetworkDetailPage,
}))
const PortalLandingPage = lazy(async () => ({
  default: (await loadPortalPages()).PortalLandingPage,
}))
const PortalClientsPage = lazy(async () => ({
  default: (await loadPortalPages()).PortalClientsPage,
}))
const PortalDevicesPage = lazy(async () => ({
  default: (await loadPortalPages()).PortalDevicesPage,
}))
const PortalDeviceDetailPage = lazy(async () => ({
  default: (await loadPortalPages()).PortalDeviceDetailPage,
}))

const PortalNetworksPage = lazy(async () => ({
  default: (await loadPortalNetworkPages()).PortalNetworksPage,
}))
const PortalNetworkDetailPage = lazy(async () => ({
  default: (await loadPortalNetworkPages()).PortalNetworkDetailPage,
}))

function RouteLoading() {
  return (
    <main aria-busy="true" className="grid min-h-[60vh] place-items-center p-6">
      <p role="status">Loading page...</p>
    </main>
  )
}

function LandingPage() {
  const session = usePrincipalSession()
  const destination = hasPermission(session, routePermissions.clients)
    ? '/clients'
    : '/portal'
  return <Navigate replace to={destination} />
}

export default function App() {
  const location = useLocation()

  return (
    <RouteErrorBoundary key={location.key}>
      <Suspense fallback={<RouteLoading />}>
        <Routes location={location}>
          <Route element={<AppShell />}>
            <Route index element={<LandingPage />} />
            <Route element={<PortalLandingPage />} path="portal" />
            <Route element={<PortalClientsPage />} path="portal/clients" />
            <Route element={<PortalDevicesPage />} path="portal/devices" />
            <Route element={<PortalNetworksPage />} path="portal/networks" />
            <Route
              element={<PortalNetworkDetailPage />}
              path="portal/networks/:networkId"
            />
            <Route
              element={<PortalDeviceDetailPage />}
              path="portal/devices/:deviceId"
            />
            <Route
              element={
                <RequirePermission permission={routePermissions.devices}>
                  <DeviceListPage />
                </RequirePermission>
              }
              path="devices"
            />
            <Route
              element={
                <RequirePermission permission={routePermissions.createDevice}>
                  <CreateDevicePage />
                </RequirePermission>
              }
              path="devices/new"
            />
            <Route
              element={
                <RequirePermission permission={routePermissions.deviceDetail}>
                  <DeviceDetailPage />
                </RequirePermission>
              }
              path="devices/:deviceId"
            />
            <Route
              element={
                <RequirePermission permission={routePermissions.editDevice}>
                  <EditDevicePage />
                </RequirePermission>
              }
              path="devices/:deviceId/edit"
            />
            <Route
              path="users"
              element={
                <RequirePermission permission={routePermissions.users}>
                  <UserListPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/new"
              element={
                <RequirePermission permission={routePermissions.createUser}>
                  <CreateUserPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/:userId"
              element={
                <RequirePermission permission={routePermissions.userDetail}>
                  <UserDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="users/:userId/edit"
              element={
                <RequirePermission permission={routePermissions.editUser}>
                  <EditUserPage />
                </RequirePermission>
              }
            />
            <Route
              path="clients"
              element={
                <RequirePermission permission={routePermissions.clients}>
                  <ClientListPage />
                </RequirePermission>
              }
            />
            <Route
              path="clients/:clientName"
              element={
                <RequirePermission permission={routePermissions.clientDetail}>
                  <ClientDetailPage />
                </RequirePermission>
              }
            />
            <Route
              path="server"
              element={
                <RequirePermission permission={routePermissions.server}>
                  <ServerPage />
                </RequirePermission>
              }
            />
            <Route
              path="server/routes"
              element={
                <RequirePermission permission={routePermissions.serverRoutes}>
                  <ServerRoutesPage />
                </RequirePermission>
              }
            />
            <Route
              path="networks"
              element={
                <RequirePermission permission={routePermissions.networks}>
                  <NetworkListPage />
                </RequirePermission>
              }
            />
            <Route
              path="networks/:networkId"
              element={
                <RequirePermission permission={routePermissions.networkDetail}>
                  <NetworkDetailPage />
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
