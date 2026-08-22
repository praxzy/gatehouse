import { AppWindow, ArrowUpRight, Globe2, KeyRound, Users } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { ApplicationSummary } from '@/api/applications'
import { CreateApplicationSheet } from '@/applications/CreateApplicationSheet'
import { useApplications } from '@/applications/queries'
import { useCurrentUser } from '@/auth/currentUser'
import { hasPermission, permissions } from '@/auth/permissions'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'
import { useRoles } from '@/roles/queries'

export function ApplicationsPage() {
  const applications = useApplications()
  const currentUser = useCurrentUser()

  const canManageApplications = currentUser.data
    ? hasPermission(currentUser.data.permissions, permissions.applicationManage)
    : false

  const canReadRoles = currentUser.data
    ? hasPermission(currentUser.data.permissions, permissions.roleRead)
    : false

  const roles = useRoles(canManageApplications && canReadRoles)

  if (applications.isPending) {
    return (
      <PageContainer>
        <div
          className="flex min-h-80 items-center justify-center gap-3 text-sm font-medium text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Loading applications
        </div>
      </PageContainer>
    )
  }

  if (applications.isError) {
    return (
      <PageContainer>
        <Surface className="mx-auto max-w-xl p-6">
          <h1 className="font-heading text-2xl font-medium">Applications couldn’t be loaded</h1>

          <div className="mt-4">
            <RequestError error={applications.error} />
          </div>

          <Button
            type="button"
            variant="outline"
            onClick={() => applications.refetch()}
            className="mt-5 rounded-lg"
          >
            Try again
          </Button>
        </Surface>
      </PageContainer>
    )
  }

  const availableRoles = roles.data?.roles ?? []

  return (
    <PageContainer>
      <header className="motion-enter flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-[0.67rem] tracking-[0.14em] text-muted-foreground uppercase">
            Client registration
          </p>

          <h1 className="mt-2 font-heading text-4xl font-medium tracking-[-0.035em]">
            Applications
          </h1>

          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            {applicationCountLabel(applications.data.applications.length)}
          </p>
        </div>

        {canManageApplications && applications.data.applications.length > 0 && (
          <CreateApplicationSheet roles={availableRoles} />
        )}
      </header>

      {applications.data.applications.length === 0 ? (
        <EmptyApplications canManage={canManageApplications} roles={availableRoles} />
      ) : (
        <div className="motion-enter motion-enter-delay-1 mt-8 grid gap-4 xl:grid-cols-2">
          {applications.data.applications.map((application) => (
            <ApplicationCard key={application.application_id} application={application} />
          ))}
        </div>
      )}
    </PageContainer>
  )
}

function ApplicationCard({ application }: { application: ApplicationSummary }) {
  const confidential = application.client_type === 'confidential'

  return (
    <Surface className="group flex min-h-64 flex-col p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <div
            className="grid size-11 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary"
            aria-hidden="true"
          >
            <AppWindow size={19} />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-base font-semibold">{application.name}</h2>

              <span className="rounded-full bg-primary/8 px-2 py-0.5 text-[0.62rem] font-semibold text-primary">
                {application.status}
              </span>
            </div>

            <p className="mt-1 truncate font-mono text-[0.68rem] text-muted-foreground">
              {application.client_id}
            </p>
          </div>
        </div>

        <Button asChild type="button" variant="ghost" size="icon" className="shrink-0 rounded-lg">
          <Link
            to={`/app/applications/${application.application_id}`}
            aria-label={`Open ${application.name}`}
          >
            <ArrowUpRight aria-hidden="true" />
          </Link>
        </Button>
      </div>

      <p className="mt-5 text-sm leading-6 text-muted-foreground">
        {application.description || 'No description provided.'}
      </p>

      <div className="mt-auto grid grid-cols-2 gap-3 pt-6">
        <ApplicationFact
          icon={confidential ? KeyRound : Globe2}
          label="Client"
          value={confidential ? 'Confidential' : 'Public'}
        />

        <ApplicationFact
          icon={Users}
          label="Access"
          value={
            application.access_mode === 'all_active_members'
              ? 'All members'
              : `${application.allowed_role_count} ${
                  application.allowed_role_count === 1 ? 'role' : 'roles'
                }`
          }
        />
      </div>

      <div className="mt-4 border-t border-border pt-4 text-xs text-muted-foreground">
        {application.redirect_uri_count}{' '}
        {application.redirect_uri_count === 1 ? 'redirect URI' : 'redirect URIs'}
      </div>
    </Surface>
  )
}

function ApplicationFact({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof AppWindow
  label: string
  value: string
}) {
  return (
    <div className="rounded-xl border border-border bg-muted/30 p-3">
      <div className="flex items-center gap-2 text-muted-foreground">
        <Icon size={14} aria-hidden="true" />

        <span className="text-[0.62rem] font-semibold tracking-[0.1em] uppercase">{label}</span>
      </div>

      <p className="mt-2 text-sm font-medium">{value}</p>
    </div>
  )
}

function EmptyApplications({
  canManage,
  roles,
}: {
  canManage: boolean
  roles: Parameters<typeof CreateApplicationSheet>[0]['roles']
}) {
  return (
    <Surface className="motion-enter motion-enter-delay-1 mt-8 flex min-h-96 flex-col items-center justify-center px-6 py-12 text-center">
      <div
        className="grid size-12 place-items-center rounded-xl bg-primary/10 text-primary"
        aria-hidden="true"
      >
        <AppWindow size={21} />
      </div>

      <h2 className="mt-5 font-heading text-2xl font-medium">No applications yet</h2>

      <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">
        Register an application to connect it to Gatehouse.
      </p>

      {canManage && (
        <div className="mt-6">
          <CreateApplicationSheet roles={roles} />
        </div>
      )}
    </Surface>
  )
}

function applicationCountLabel(count: number) {
  if (count === 0) {
    return 'No applications registered.'
  }

  return `${count} registered ${count === 1 ? 'application' : 'applications'}.`
}

function PageContainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-376 px-5 py-7 sm:px-7 lg:px-10 lg:py-9">{children}</div>
  )
}
