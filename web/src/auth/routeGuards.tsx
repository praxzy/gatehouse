import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { APIError, isServiceUnavailableError } from '@/api/client'
import { ServiceUnavailablePage } from '@/components/ServiceUnavailablePage'
import { Spinner } from '@/components/ui/spinner'
import { useCurrentUser } from './currentUser'
import { authenticatedDestination } from './routing'
import type { Permission } from '@/auth/permissions'
import { hasPermission } from '@/auth/permissions'

export function PublicOnlyRoute() {
  const currentUser = useCurrentUser()

  if (currentUser.isPending) {
    return <AuthenticationLoading />
  }

  if (currentUser.isError) {
    if (isUnauthenticated(currentUser.error)) {
      return <Outlet />
    }

    if (isServiceUnavailableError(currentUser.error)) {
      return <CurrentUserUnavailable currentUser={currentUser} />
    }

    throw currentUser.error
  }

  return <Navigate to={authenticatedDestination(currentUser.data)} replace />
}

export function RequireSession() {
  const currentUser = useCurrentUser()
  const location = useLocation()

  if (currentUser.isPending) {
    return <AuthenticationLoading />
  }

  if (currentUser.isError) {
    if (isUnauthenticated(currentUser.error)) {
      const returnTo = location.pathname + location.search

      return <Navigate to={`/login?return_to=${encodeURIComponent(returnTo)}`} replace />
    }

    if (isServiceUnavailableError(currentUser.error)) {
      return <CurrentUserUnavailable currentUser={currentUser} />
    }

    throw currentUser.error
  }

  return <Outlet />
}

export function RequireFullyAuthenticated() {
  const currentUser = useCurrentUser()
  const location = useLocation()

  if (currentUser.isPending) {
    return <AuthenticationLoading />
  }

  if (currentUser.isError) {
    if (isUnauthenticated(currentUser.error)) {
      const returnTo = location.pathname + location.search

      return <Navigate to={`/login?return_to=${encodeURIComponent(returnTo)}`} replace />
    }

    if (isServiceUnavailableError(currentUser.error)) {
      return <CurrentUserUnavailable currentUser={currentUser} />
    }

    throw currentUser.error
  }

  if (!currentUser.data.fully_authenticated) {
    const returnTo = location.pathname + location.search

    return <Navigate to={authenticatedDestination(currentUser.data, returnTo)} replace />
  }

  return <Outlet />
}

function isUnauthenticated(error: unknown) {
  return error instanceof APIError && error.status === 401
}

function CurrentUserUnavailable({
  currentUser,
}: {
  currentUser: ReturnType<typeof useCurrentUser>
}) {
  return (
    <ServiceUnavailablePage
      error={currentUser.error}
      isRetrying={currentUser.isFetching}
      onRetry={() => void currentUser.refetch()}
    />
  )
}

function AuthenticationLoading() {
  return (
    <main
      aria-busy="true"
      aria-live="polite"
      className="grid min-h-svh place-items-center bg-background"
    >
      <div className="flex items-center gap-3 text-sm font-medium text-muted-foreground">
        <Spinner />
        <p>Checking your session…</p>
      </div>
    </main>
  )
}

export function RequirePermission({ permission }: { permission: Permission }) {
  const currentUser = useCurrentUser()

  if (currentUser.isPending) {
    return <AuthenticationLoading />
  }

  if (currentUser.isError) {
    if (isUnauthenticated(currentUser.error)) {
      return <Navigate to="/login" replace />
    }

    if (isServiceUnavailableError(currentUser.error)) {
      return <CurrentUserUnavailable currentUser={currentUser} />
    }

    throw currentUser.error
  }

  if (!hasPermission(currentUser.data.permissions, permission)) {
    return <Navigate to="/app" replace />
  }

  return <Outlet />
}
