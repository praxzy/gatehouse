import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { APIError } from '@/api/client'
import { useCurrentUser } from './currentUser'
import { authenticatedDestination } from './routing'

export function PublicOnlyRoute() {
  const currentUser = useCurrentUser()

  if (currentUser.isPending) {
    return <AuthenticationLoading />
  }

  if (currentUser.isError) {
    if (isUnauthenticated(currentUser.error)) {
      return <Outlet />
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

function AuthenticationLoading() {
  return (
    <main aria-busy="true" aria-live="polite">
      <p>Checking your session…</p>
    </main>
  )
}
