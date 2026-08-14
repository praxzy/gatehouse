import { RefreshCw, Unplug } from 'lucide-react'
import { APIError } from '@/api/client'
import { ErrorReference } from '@/components/ErrorReference'
import { GatehouseBrand } from '@/components/GatehouseBrand'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

type ServiceUnavailablePageProps = {
  error: unknown
  isRetrying: boolean
  onRetry: () => void
}

export function ServiceUnavailablePage({
  error,
  isRetrying,
  onRetry,
}: ServiceUnavailablePageProps) {
  const requestID = error instanceof APIError ? error.requestId : undefined

  return (
    <main className="grid min-h-svh place-items-center bg-background px-5 py-10">
      <section className="motion-enter w-full max-w-lg rounded-2xl border border-border/70 bg-card p-6 shadow-[0_24px_80px_-48px_rgba(10,44,31,0.45)] sm:p-8">
        <GatehouseBrand showDescriptor={false} />

        <div className="mt-10 grid size-11 place-items-center rounded-xl border border-primary/10 bg-primary/7 text-primary">
          <Unplug className="size-5" aria-hidden="true" />
        </div>

        <p className="mt-7 font-mono text-[0.67rem] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
          Connection unavailable
        </p>

        <h1 className="mt-2 max-w-md font-heading text-3xl leading-tight font-medium tracking-tight text-foreground sm:text-4xl">
          Gatehouse is temporarily unavailable
        </h1>

        <p className="mt-4 max-w-md text-sm leading-6 text-muted-foreground">
          We couldn’t connect to the service. Try again in a moment.
        </p>

        <div className="mt-7">
          <Button type="button" size="lg" onClick={onRetry} disabled={isRetrying}>
            <RefreshCw className={cn('size-4', isRetrying && 'animate-spin')} aria-hidden="true" />
            {isRetrying ? 'Trying again…' : 'Try again'}
          </Button>
        </div>

        <ErrorReference requestId={requestID} />
      </section>
    </main>
  )
}
