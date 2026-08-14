import { Component } from 'react'
import type { ReactNode } from 'react'
import { RefreshCw, TriangleAlert } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import { APIError } from '@/api/client'
import { Button } from '@/components/ui/button'
import { ErrorReference } from './ErrorReference'
import { GatehouseBrand } from './GatehouseBrand'

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
    <main className="grid min-h-svh place-items-center bg-background px-5 py-10">
      <section className="motion-enter w-full max-w-lg rounded-2xl border border-border/70 bg-card p-6 shadow-[0_24px_80px_-48px_rgba(10,44,31,0.45)] sm:p-8">
        <GatehouseBrand showDescriptor={false} />

        <div className="mt-10 grid size-11 place-items-center rounded-xl border border-destructive/10 bg-destructive/7 text-destructive">
          <TriangleAlert className="size-5" aria-hidden="true" />
        </div>

        <p className="mt-7 font-mono text-[0.67rem] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
          Application error
        </p>

        <h1 className="mt-2 font-heading text-3xl leading-tight font-medium tracking-tight text-foreground sm:text-4xl">
          We couldn’t load this page
        </h1>

        <p className="mt-4 text-sm leading-6 text-muted-foreground">
          Something unexpected happened. Reload the page to try again.
        </p>

        <ErrorReference requestId={requestID} />

        <div className="mt-7">
          <Button type="button" size="lg" onClick={() => window.location.reload()}>
            <RefreshCw className="size-4" aria-hidden="true" />
            Reload page
          </Button>
        </div>
      </section>
    </main>
  )
}

export function AppErrorBoundary({ children }: AppErrorBoundaryProps) {
  const location = useLocation()
  const resetKey = location.pathname + location.search

  return <Boundary key={resetKey}>{children}</Boundary>
}
