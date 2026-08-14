import { Component } from 'react'
import type { ReactNode } from 'react'
import { useLocation } from 'react-router-dom'
import { APIError } from '@/api/client'
import { ErrorReference } from './ErrorReference'

type AppErrorBoundaryProps = {
  children: ReactNode
}

type BoundaryProps = {
  children: ReactNode
}

type BoundaryState = {
  error: unknown
}

class Boundary extends Component<BoundaryProps, BoundaryState> {
  state: BoundaryState = {
    error: null,
  }

  static getDerivedStateFromError(error: unknown): BoundaryState {
    return { error }
  }

  render() {
    if (this.state.error !== null) {
      return <FatalError error={this.state.error} />
    }

    return this.props.children
  }
}

function FatalError({ error }: { error: unknown }) {
  const requestID = error instanceof APIError ? error.requestId : undefined

  return (
    <main className="fatal-error">
      <div>
        <p className="eyebrow">Gatehouse Admin</p>
        <h1>We couldn’t load this page</h1>
        <p>Try the request again.</p>

        <ErrorReference requestId={requestID} />

        <div className="fatal-error-actions">
          <button type="button" onClick={() => window.location.reload()}>
            Try again
          </button>

          <a href="/login">Return to sign in</a>
        </div>
      </div>
    </main>
  )
}

export function AppErrorBoundary({ children }: AppErrorBoundaryProps) {
  const location = useLocation()
  const resetKey = location.pathname + location.search

  return <Boundary key={resetKey}>{children}</Boundary>
}
