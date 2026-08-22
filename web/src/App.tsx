import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import {
  PublicOnlyRoute,
  RequireFullyAuthenticated,
  RequireSession,
  RequirePermission,
} from '@/auth/routeGuards'
import { Spinner } from '@/components/ui/spinner'
import { permissions } from '@/auth/permissions'

const AuthLayout = lazy(() =>
  import('./layouts/AuthLayout').then((module) => ({
    default: module.AuthLayout,
  })),
)

const AdminLayout = lazy(() =>
  import('./layouts/AdminLayout').then((module) => ({
    default: module.AdminLayout,
  })),
)

const LoginPage = lazy(() =>
  import('./pages/LoginPage').then((module) => ({
    default: module.LoginPage,
  })),
)

const RegisterPage = lazy(() =>
  import('./pages/RegisterPage').then((module) => ({
    default: module.RegisterPage,
  })),
)

const VerifyEmailPage = lazy(() =>
  import('./pages/VerifyEmailPage').then((module) => ({
    default: module.VerifyEmailPage,
  })),
)

const AcceptInvitationPage = lazy(() =>
  import('./pages/AcceptInvitationPage').then((module) => ({
    default: module.AcceptInvitationPage,
  })),
)

const MFAEnrollmentPage = lazy(() =>
  import('./pages/MFAEnrollmentPage').then((module) => ({
    default: module.MFAEnrollmentPage,
  })),
)

const MFAChallengePage = lazy(() =>
  import('./pages/MFAChallengePage').then((module) => ({
    default: module.MFAChallengePage,
  })),
)

const DashboardPage = lazy(() =>
  import('./pages/DashboardPage').then((module) => ({
    default: module.DashboardPage,
  })),
)

const MembersPage = lazy(() =>
  import('./pages/MembersPage').then((module) => ({
    default: module.MembersPage,
  })),
)

const RolesPage = lazy(() =>
  import('./pages/RolesPage').then((module) => ({
    default: module.RolesPage,
  })),
)

const ApplicationsPage = lazy(() =>
  import('./pages/ApplicationsPage').then((module) => ({
    default: module.ApplicationsPage,
  })),
)

const ApplicationDetailPage = lazy(() =>
  import('./pages/ApplicationDetailPage').then((module) => ({
    default: module.ApplicationDetailPage,
  })),
)

function App() {
  return (
    <Suspense fallback={<RouteLoading />}>
      <Routes>
        <Route element={<AuthLayout />}>
          <Route path="/verify-email" element={<VerifyEmailPage />} />
          <Route path="/accept-invitation" element={<AcceptInvitationPage />} />

          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
          </Route>

          <Route element={<RequireSession />}>
            <Route path="/mfa/enroll" element={<MFAEnrollmentPage />} />
            <Route path="/mfa/challenge" element={<MFAChallengePage />} />
          </Route>
        </Route>

        <Route element={<RequireFullyAuthenticated />}>
          <Route element={<AdminLayout />}>
            <Route path="/app" element={<DashboardPage />} />

            <Route element={<RequirePermission permission={permissions.memberRead} />}>
              <Route path="/app/members" element={<MembersPage />} />
            </Route>

            <Route element={<RequirePermission permission={permissions.roleRead} />}>
              <Route path="/app/roles" element={<RolesPage />} />

              <Route element={<RequirePermission permission={permissions.applicationRead} />}>
                <Route path="/app/applications" element={<ApplicationsPage />} />

                <Route
                  path="/app/applications/:applicationId"
                  element={<ApplicationDetailPage />}
                />
              </Route>
            </Route>
          </Route>
        </Route>

        <Route path="/" element={<Navigate to="/app" replace />} />
        <Route path="*" element={<Navigate to="/app" replace />} />
      </Routes>
    </Suspense>
  )
}

function RouteLoading() {
  return (
    <main
      aria-busy="true"
      aria-live="polite"
      className="grid min-h-svh place-items-center bg-background"
    >
      <div className="flex items-center gap-3 text-sm font-medium text-muted-foreground">
        <Spinner />
        Opening Gatehouse
      </div>
    </main>
  )
}

export default App
