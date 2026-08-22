import { ArrowLeft, Check, Copy, Globe2, KeyRound, Link2, Users } from 'lucide-react'
import { Link, Navigate, useParams } from 'react-router-dom'
import { toast } from 'sonner'
import { useApplication } from '@/applications/queries'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'

export function ApplicationDetailPage() {
  const { applicationId = '' } = useParams()
  const application = useApplication(applicationId)

  if (applicationId === '') {
    return <Navigate to="/app/applications" replace />
  }

  if (application.isPending) {
    return (
      <PageContainer>
        <div
          className="flex min-h-80 items-center justify-center gap-3 text-sm font-medium text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Loading application
        </div>
      </PageContainer>
    )
  }

  if (application.isError) {
    return (
      <PageContainer>
        <Button asChild variant="ghost" className="mb-5 rounded-lg">
          <Link to="/app/applications">
            <ArrowLeft aria-hidden="true" />
            Applications
          </Link>
        </Button>

        <Surface className="mx-auto max-w-xl p-6">
          <h1 className="font-heading text-2xl font-medium">Application couldn’t be loaded</h1>

          <div className="mt-4">
            <RequestError error={application.error} />
          </div>

          <Button
            type="button"
            variant="outline"
            onClick={() => application.refetch()}
            className="mt-5 rounded-lg"
          >
            Try again
          </Button>
        </Surface>
      </PageContainer>
    )
  }

  const detail = application.data
  const confidential = detail.client_type === 'confidential'

  return (
    <PageContainer>
      <Button asChild variant="ghost" className="motion-enter -ml-3 rounded-lg">
        <Link to="/app/applications">
          <ArrowLeft aria-hidden="true" />
          Applications
        </Link>
      </Button>

      <header className="motion-enter mt-5 flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-mono text-[0.67rem] tracking-[0.14em] text-muted-foreground uppercase">
              Application
            </p>

            <span className="rounded-full bg-primary/8 px-2 py-0.5 text-[0.62rem] font-semibold text-primary">
              {detail.status}
            </span>
          </div>

          <h1 className="mt-2 font-heading text-4xl font-medium tracking-[-0.035em] break-words">
            {detail.name}
          </h1>

          {detail.description && (
            <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
              {detail.description}
            </p>
          )}
        </div>
      </header>

      <div className="motion-enter motion-enter-delay-1 mt-8 grid gap-5 xl:grid-cols-[minmax(0,1.3fr)_minmax(18rem,0.7fr)]">
        <div className="space-y-5">
          <Surface className="p-6">
            <div className="flex items-center gap-3">
              <div
                className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary"
                aria-hidden="true"
              >
                {confidential ? <KeyRound size={18} /> : <Globe2 size={18} />}
              </div>

              <div>
                <h2 className="text-base font-semibold">Client configuration</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {confidential ? 'Confidential client' : 'Public client'}
                </p>
              </div>
            </div>

            <div className="mt-6">
              <p className="text-[0.65rem] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
                Client ID
              </p>

              <div className="mt-2 flex items-center gap-2 rounded-xl border border-border bg-muted/35 p-3">
                <code className="min-w-0 flex-1 text-xs break-all">{detail.client_id}</code>

                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  className="shrink-0 rounded-lg"
                  onClick={() => copyClientID(detail.client_id)}
                  aria-label="Copy client ID"
                >
                  <Copy aria-hidden="true" />
                </Button>
              </div>
            </div>

            <div className="mt-5 rounded-xl border border-border bg-muted/25 p-4">
              <p className="text-sm font-medium">
                {confidential ? 'Client secret is not retrievable' : 'No client secret required'}
              </p>

              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                {confidential
                  ? 'The secret was displayed once when this application was created.'
                  : 'Public clients authenticate without storing a client secret.'}
              </p>
            </div>
          </Surface>

          <Surface className="p-6">
            <div className="flex items-center gap-3">
              <div
                className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary"
                aria-hidden="true"
              >
                <Link2 size={18} />
              </div>

              <div>
                <h2 className="text-base font-semibold">Redirect URIs</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  Redirects must match these values exactly.
                </p>
              </div>
            </div>

            <ul className="mt-6 space-y-3">
              {detail.redirect_uris.map((redirectURI) => (
                <li
                  key={redirectURI.redirect_uri_id}
                  className="flex items-start gap-3 rounded-xl border border-border bg-muted/25 p-4"
                >
                  <Check size={15} className="mt-0.5 shrink-0 text-primary" aria-hidden="true" />

                  <code className="min-w-0 text-xs leading-5 break-all">{redirectURI.uri}</code>
                </li>
              ))}
            </ul>
          </Surface>
        </div>

        <div className="space-y-5">
          <Surface className="p-6">
            <div className="flex items-center gap-3">
              <div
                className="grid size-10 place-items-center rounded-lg bg-primary/10 text-primary"
                aria-hidden="true"
              >
                <Users size={18} />
              </div>

              <div>
                <h2 className="text-base font-semibold">Application access</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {detail.access_mode === 'all_active_members'
                    ? 'Available to all active members'
                    : 'Limited to selected roles'}
                </p>
              </div>
            </div>

            {detail.access_mode === 'allowed_roles' && (
              <ul className="mt-5 space-y-2">
                {detail.allowed_roles.map((role) => (
                  <li
                    key={role.role_id}
                    className="flex items-center justify-between gap-3 rounded-xl border border-border bg-muted/25 px-4 py-3"
                  >
                    <span className="text-sm font-medium">{role.name}</span>

                    {role.is_system && (
                      <span className="text-[0.62rem] font-semibold text-muted-foreground">
                        Built in
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Surface>

          <Surface className="p-6">
            <h2 className="text-base font-semibold">Details</h2>

            <dl className="mt-5 space-y-4">
              <DetailRow label="Client type" value={formatLabel(detail.client_type)} />
              <DetailRow label="Status" value={formatLabel(detail.status)} />
              <DetailRow label="Created" value={formatDate(detail.created_at)} />
              <DetailRow label="Updated" value={formatDate(detail.updated_at)} />
            </dl>
          </Surface>
        </div>
      </div>
    </PageContainer>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border pb-4 last:border-0 last:pb-0">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-right text-sm font-medium">{value}</dd>
    </div>
  )
}

async function copyClientID(clientID: string) {
  try {
    await navigator.clipboard.writeText(clientID)
    toast.success('Client ID copied')
  } catch {
    toast.error('Could not copy client ID')
  }
}

function formatLabel(value: string) {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function PageContainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-376 px-5 py-7 sm:px-7 lg:px-10 lg:py-9">{children}</div>
  )
}
