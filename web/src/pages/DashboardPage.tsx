import {
  AppWindow,
  ArrowRight,
  ArrowUpRight,
  Check,
  CircleAlert,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  ShieldCheck,
  UserCheck,
  Users,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Link } from 'react-router-dom'
import type { ApplicationListResponse } from '@/api/applications'
import type { AuditEvent } from '@/api/audit'
import type { CurrentUser } from '@/api/auth'
import type { MemberListResponse } from '@/api/members'
import type { RoleListResponse } from '@/api/roles'
import { useApplications } from '@/applications/queries'
import { useRecentAuditEvents } from '@/audit/queries'
import { useCurrentUser } from '@/auth/currentUser'
import { hasPermission, permissions } from '@/auth/permissions'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'
import { usePointerTilt } from '@/hooks/usePointerTilt'
import { cn } from '@/lib/utils'
import { useMembers } from '@/members/queries'
import { useRoles } from '@/roles/queries'

export function DashboardPage() {
  const currentUser = useCurrentUser()
  const grantedPermissions = currentUser.data?.permissions ?? []
  const canReadMembers = hasPermission(grantedPermissions, permissions.memberRead)
  const canManageMembers = hasPermission(grantedPermissions, permissions.memberManage)
  const canReadRoles = hasPermission(grantedPermissions, permissions.roleRead)
  const canReadApplications = hasPermission(grantedPermissions, permissions.applicationRead)
  const canManageApplications = hasPermission(grantedPermissions, permissions.applicationManage)
  const canReadAudit = hasPermission(grantedPermissions, permissions.auditRead)

  const members = useMembers(canReadMembers)
  const roles = useRoles(canReadRoles)
  const applications = useApplications(canReadApplications)
  const recentAudit = useRecentAuditEvents(canReadAudit)

  if (!currentUser.data) {
    return null
  }

  const user = currentUser.data
  const canReadWorkspace = canReadMembers || canReadRoles || canReadApplications

  return (
    <div className="mx-auto w-full max-w-[94rem] px-5 py-7 sm:px-7 lg:px-10 lg:py-9">
      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(20rem,0.7fr)]">
        <BoundaryHero
          tenantName={user.tenant_name}
          tenantSlug={user.tenant_slug}
          mfaEnrolled={user.mfa_enrolled}
        />

        <AccountSecurity user={user} />
      </section>

      {canReadWorkspace && (
        <WorkspaceOverview
          members={members}
          roles={roles}
          applications={applications}
          canReadMembers={canReadMembers}
          canReadRoles={canReadRoles}
          canReadApplications={canReadApplications}
        />
      )}

      <section
        className={cn('mt-9 grid gap-5', canReadAudit && 'xl:grid-cols-[minmax(0,1fr)_23rem]')}
      >
        {canReadAudit && <BoundaryActivity audit={recentAudit} />}

        <div className={cn(canReadAudit && 'relative xl:self-stretch')}>
          <AttentionPanel
            user={user}
            members={members.data}
            applications={applications.data}
            canManageMembers={canManageMembers}
            canManageApplications={canManageApplications}
            constrainToActivity={canReadAudit}
          />
        </div>
      </section>
    </div>
  )
}

type BoundaryHeroProps = {
  tenantName: string
  tenantSlug: string
  mfaEnrolled: boolean
}

function BoundaryHero({ tenantName, tenantSlug, mfaEnrolled }: BoundaryHeroProps) {
  const pointerTilt = usePointerTilt<HTMLElement>()

  return (
    <Surface
      {...pointerTilt}
      tone="inverse"
      depth="raised"
      className="surface-gloss surface-tilt motion-enter min-h-[22rem] rounded-2xl border-white/8"
    >
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.065]"
        aria-hidden="true"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,.8) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.8) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      <div
        className="pointer-events-none absolute -right-24 bottom-0 h-[80%] w-64 rounded-t-[15rem] border border-white/12 sm:-right-16 sm:h-[88%] sm:w-[52%]"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -right-12 bottom-0 h-[62%] w-44 rounded-t-[12rem] border border-white/10 sm:right-[2%] sm:h-[70%] sm:w-[38%]"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute right-2 bottom-0 h-[44%] w-24 rounded-t-[8rem] border border-gatehouse-brass/35 sm:right-[12%] sm:h-[51%] sm:w-[21%]"
        aria-hidden="true"
      />

      <div
        className="pointer-events-none absolute right-14 bottom-0 h-[44%] w-px bg-gatehouse-brass/35 sm:right-[22.5%] sm:h-[51%]"
        aria-hidden="true"
      />

      <div className="relative z-10 flex min-h-[22rem] flex-col p-6 sm:p-8">
        <div className="flex items-center gap-2 text-xs font-semibold text-emerald-200">
          <span className="relative flex size-2">
            <span className="absolute inset-0 rounded-full bg-emerald-300/35" />
            <span className="relative m-auto size-1.5 rounded-full bg-emerald-300" />
          </span>
          Active
        </div>

        <div className="my-auto max-w-xl py-9">
          <p className="font-mono text-[0.67rem] tracking-[0.15em] text-white/42 uppercase">
            tenant / {tenantSlug}
          </p>

          <h2 className="mt-3 max-w-lg font-heading text-4xl leading-[0.98] font-medium tracking-[-0.04em] sm:text-5xl">
            {tenantName}
          </h2>
        </div>

        <div className="grid max-w-xl grid-cols-2 gap-px overflow-hidden rounded-lg border border-white/10 bg-white/10 sm:grid-cols-2">
          <BoundaryFact label="Organization" value="Active" />
          <BoundaryFact label="Your MFA" value={mfaEnrolled ? 'Enabled' : 'Attention'} />
        </div>
      </div>
    </Surface>
  )
}

function BoundaryFact({
  label,
  value,
  className = '',
}: {
  label: string
  value: string
  className?: string
}) {
  return (
    <div className={`bg-gatehouse-forest/92 px-4 py-3 ${className}`}>
      <p className="text-[0.62rem] font-semibold tracking-[0.12em] text-white/35 uppercase">
        {label}
      </p>
      <p className="mt-1 text-xs font-semibold text-white/82">{value}</p>
    </div>
  )
}

function AccountSecurity({ user }: { user: CurrentUser }) {
  return (
    <Surface className="motion-enter motion-enter-delay-1 flex flex-col p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[0.64rem] tracking-[0.13em] text-muted-foreground uppercase">
            Your account
          </p>
          <h2 className="mt-2 font-heading text-2xl font-medium tracking-[-0.025em]">
            Session security
          </h2>
        </div>

        <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
          <ShieldCheck size={18} aria-hidden="true" />
        </div>
      </div>

      <dl className="mt-6 divide-y divide-border border-y border-border">
        <AccountFact
          icon={LockKeyhole}
          label="Signed in with"
          value={authenticationLabel(user.authentication_level)}
        />
        <AccountFact
          icon={Fingerprint}
          label="Multi-factor authentication"
          value={user.mfa_enrolled ? 'Enabled' : 'Not enabled'}
          attention={!user.mfa_enrolled}
        />
        <AccountFact
          icon={UserCheck}
          label="Session expires"
          value={formatSessionExpiry(user.session_expires_at)}
        />
      </dl>

      {!user.mfa_enrolled && (
        <Link
          to="/mfa/enroll"
          className="mt-auto flex items-center justify-between pt-5 text-sm font-semibold text-primary"
        >
          Set up MFA
          <ArrowUpRight size={16} aria-hidden="true" />
        </Link>
      )}
    </Surface>
  )
}

function AccountFact({
  icon: Icon,
  label,
  value,
  attention = false,
}: {
  icon: LucideIcon
  label: string
  value: string
  attention?: boolean
}) {
  return (
    <div className="grid grid-cols-[auto_1fr] gap-3 py-4">
      <div className="grid size-8 place-items-center rounded-lg bg-muted text-muted-foreground">
        <Icon size={15} aria-hidden="true" />
      </div>
      <div className="min-w-0">
        <dt className="text-xs text-muted-foreground">{label}</dt>
        <dd className={cn('mt-1 text-sm font-semibold', attention && 'text-gatehouse-brass')}>
          {value}
        </dd>
      </div>
    </div>
  )
}

function WorkspaceOverview({
  members,
  roles,
  applications,
  canReadMembers,
  canReadRoles,
  canReadApplications,
}: {
  members: ReturnType<typeof useMembers>
  roles: ReturnType<typeof useRoles>
  applications: ReturnType<typeof useApplications>
  canReadMembers: boolean
  canReadRoles: boolean
  canReadApplications: boolean
}) {
  const visibleCards = [canReadMembers, canReadRoles, canReadApplications].filter(Boolean).length

  return (
    <section className="mt-9" aria-labelledby="workspace-overview-heading">
      <div className="motion-enter motion-enter-delay-2 mb-4">
        <h2
          id="workspace-overview-heading"
          className="font-heading text-2xl font-medium tracking-tight"
        >
          Workspace at a glance
        </h2>
      </div>

      <div
        className={cn(
          'grid gap-4',
          visibleCards === 2 && 'md:grid-cols-2',
          visibleCards === 3 && 'md:grid-cols-3',
        )}
      >
        {canReadMembers && (
          <ResourceSummaryCard
            icon={Users}
            label="Members"
            href="/app/members"
            query={members}
            value={members.data?.members.filter((member) => member.status === 'active').length}
            detail={memberSummary(members.data)}
            className="motion-enter motion-enter-delay-3"
          />
        )}

        {canReadRoles && (
          <ResourceSummaryCard
            icon={KeyRound}
            label="Roles"
            href="/app/roles"
            query={roles}
            value={roles.data?.roles.length}
            detail={roleSummary(roles.data)}
            className="motion-enter motion-enter-delay-4"
          />
        )}

        {canReadApplications && (
          <ResourceSummaryCard
            icon={AppWindow}
            label="Applications"
            href="/app/applications"
            query={applications}
            value={applications.data?.applications.length}
            detail={applicationSummary(applications.data)}
            className="motion-enter motion-enter-delay-5"
          />
        )}
      </div>
    </section>
  )
}

function ResourceSummaryCard({
  icon: Icon,
  label,
  href,
  query,
  value,
  detail,
  className,
}: {
  icon: LucideIcon
  label: string
  href: string
  query: { isPending: boolean; isError: boolean }
  value?: number
  detail: string
  className?: string
}) {
  return (
    <Link to={href} className={cn('group block rounded-xl outline-none', className)}>
      <Surface className="flex min-h-44 flex-col p-5 transition-colors [transition-duration:var(--motion-duration-standard)] [transition-timing-function:var(--motion-ease-standard)] group-hover:border-primary/25 group-hover:bg-primary/[0.025] group-focus-visible:border-primary/25 group-focus-visible:bg-primary/[0.025] group-focus-visible:ring-3 group-focus-visible:ring-ring/30 motion-reduce:transition-none">
        <div className="flex items-center justify-between">
          <div className="grid size-10 place-items-center rounded-xl bg-primary/10 text-primary">
            <Icon size={18} aria-hidden="true" />
          </div>
          <ArrowUpRight
            size={16}
            className="text-muted-foreground transition-colors [transition-duration:var(--motion-duration-standard)] [transition-timing-function:var(--motion-ease-standard)] group-hover:text-foreground motion-reduce:transition-none"
            aria-hidden="true"
          />
        </div>

        <div className="mt-auto pt-6">
          <p className="text-xs font-semibold tracking-[0.08em] text-muted-foreground uppercase">
            {label}
          </p>
          {query.isPending ? (
            <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
              <Spinner />
              Loading
            </div>
          ) : query.isError ? (
            <p className="mt-3 text-sm font-medium text-destructive">Unavailable</p>
          ) : (
            <div className="mt-2 flex items-end justify-between gap-4">
              <p className="font-heading text-4xl leading-none font-medium">{value ?? 0}</p>
              <p className="text-right text-xs leading-5 text-muted-foreground">{detail}</p>
            </div>
          )}
        </div>
      </Surface>
    </Link>
  )
}

function BoundaryActivity({ audit }: { audit: ReturnType<typeof useRecentAuditEvents> }) {
  return (
    <Surface className="motion-enter motion-enter-delay-4">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <p className="text-sm font-semibold">Recent activity</p>
          <p className="mt-1 text-xs text-muted-foreground">Latest identity and access events</p>
        </div>
        <Link
          to="/app/audit"
          className="flex items-center gap-1 text-xs font-semibold text-primary"
        >
          View all
          <ArrowUpRight size={14} aria-hidden="true" />
        </Link>
      </div>

      {audit.isPending ? (
        <div
          className="flex min-h-56 items-center justify-center gap-3 text-sm text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Loading activity
        </div>
      ) : audit.isError ? (
        <div className="grid min-h-56 place-items-center gap-3 px-6 py-10 text-center">
          <p className="text-sm text-muted-foreground">Activity couldn’t be loaded.</p>
          <Button type="button" variant="outline" onClick={() => audit.refetch()}>
            Try again
          </Button>
        </div>
      ) : audit.data.events.length === 0 ? (
        <div className="grid min-h-56 place-items-center px-6 py-10 text-center">
          <div>
            <p className="text-sm font-medium">No activity yet</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Security events will appear here as your organization uses Gatehouse.
            </p>
          </div>
        </div>
      ) : (
        <ul className="divide-y divide-border px-5">
          {audit.data.events.map((event) => (
            <li key={event.event_id} className="flex items-start justify-between gap-4 py-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="text-sm font-medium">{activityLabel(event)}</p>
                  <OutcomeBadge outcome={event.outcome} />
                </div>
                <p className="mt-1 truncate text-xs text-muted-foreground">
                  {event.actor_display_name ||
                    event.actor_email ||
                    event.actor_user_id ||
                    event.actor_kind}
                </p>
              </div>
              <time
                dateTime={event.occurred_at}
                title={new Date(event.occurred_at).toLocaleString()}
                className="shrink-0 text-xs text-muted-foreground"
              >
                {formatActivityTime(event.occurred_at)}
              </time>
            </li>
          ))}
        </ul>
      )}
    </Surface>
  )
}

function OutcomeBadge({ outcome }: { outcome: AuditEvent['outcome'] }) {
  return (
    <span
      className={cn(
        'rounded-full px-2 py-0.5 text-[0.6rem] font-semibold capitalize',
        outcome === 'success' && 'bg-primary/8 text-primary',
        outcome === 'denied' && 'bg-gatehouse-brass/12 text-gatehouse-brass',
        outcome === 'failure' && 'bg-destructive/10 text-destructive',
      )}
    >
      {outcome}
    </span>
  )
}

function activityLabel(event: AuditEvent) {
  const label = event.event_type.replaceAll(/[._]/g, ' ')
  return label.charAt(0).toUpperCase() + label.slice(1)
}

type AttentionItem = {
  id: string
  title: string
  description: string
  href: string
  action: string
}

function AttentionPanel({
  user,
  members,
  applications,
  canManageMembers,
  canManageApplications,
  constrainToActivity,
}: {
  user: CurrentUser
  members?: MemberListResponse
  applications?: ApplicationListResponse
  canManageMembers: boolean
  canManageApplications: boolean
  constrainToActivity: boolean
}) {
  const items = attentionItems({
    user,
    members,
    applications,
    canManageMembers,
    canManageApplications,
  })

  return (
    <Surface
      className={cn(
        'motion-enter motion-enter-delay-5 self-start p-5',
        constrainToActivity && 'xl:absolute xl:inset-x-0 xl:top-0 xl:max-h-full xl:overflow-y-auto',
      )}
    >
      <div className="flex items-center gap-3">
        <div
          className={cn(
            'grid size-9 place-items-center rounded-lg',
            items.length === 0
              ? 'bg-primary/10 text-primary'
              : 'bg-gatehouse-brass/12 text-gatehouse-brass',
          )}
        >
          {items.length === 0 ? (
            <Check size={17} aria-hidden="true" />
          ) : (
            <CircleAlert size={17} aria-hidden="true" />
          )}
        </div>

        <div>
          <p className="text-sm font-semibold">Needs your attention</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {items.length === 0 ? 'No action needed right now' : itemCountLabel(items.length)}
          </p>
        </div>
      </div>

      {items.length === 0 ? (
        <div className="mt-6 rounded-xl border border-primary/15 bg-primary/[0.045] p-4">
          <p className="text-sm font-medium">Everything visible to you looks in order.</p>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            Gatehouse will surface account and access-policy actions here.
          </p>
        </div>
      ) : (
        <ul className="mt-5 divide-y divide-border">
          {items.map((item) => (
            <li key={item.id} className="py-4 first:pt-0 last:pb-0">
              <p className="text-sm font-semibold">{item.title}</p>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">{item.description}</p>
              <Link
                to={item.href}
                className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-primary"
              >
                {item.action}
                <ArrowRight size={13} aria-hidden="true" />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Surface>
  )
}

function attentionItems({
  user,
  members,
  applications,
  canManageMembers,
  canManageApplications,
}: {
  user: CurrentUser
  members?: MemberListResponse
  applications?: ApplicationListResponse
  canManageMembers: boolean
  canManageApplications: boolean
}) {
  const items: AttentionItem[] = []

  if (!user.mfa_enrolled) {
    items.push({
      id: 'mfa',
      title: 'Protect your account with MFA',
      description: 'Add a second factor before performing more administrative work.',
      href: '/mfa/enroll',
      action: 'Set up MFA',
    })
  }

  if (canManageMembers && members && members.invitations.length > 0) {
    items.push({
      id: 'invitations',
      title: `${members.invitations.length} pending ${members.invitations.length === 1 ? 'invitation' : 'invitations'}`,
      description: 'Review outstanding invitations and their expiration dates.',
      href: '/app/members',
      action: 'Review invitations',
    })
  }

  if (canManageApplications && applications) {
    if (applications.applications.length === 0) {
      items.push({
        id: 'first-application',
        title: 'Register your first application',
        description: 'Create an OIDC client to start using Gatehouse for sign-in.',
        href: '/app/applications',
        action: 'Register application',
      })
    } else {
      const applicationsWithoutRoles = applications.applications.filter(
        (application) =>
          application.status === 'active' &&
          application.access_mode === 'allowed_roles' &&
          application.allowed_role_count === 0,
      ).length

      if (applicationsWithoutRoles > 0) {
        items.push({
          id: 'application-policies',
          title: `${applicationsWithoutRoles} ${applicationsWithoutRoles === 1 ? 'application has' : 'applications have'} no allowed roles`,
          description: 'No member can sign in until an allowed role is added to the access policy.',
          href: '/app/applications',
          action: 'Review access policies',
        })
      }
    }
  }

  return items
}

function memberSummary(data?: MemberListResponse) {
  if (!data) return ''

  const pending = data.invitations.length
  return pending === 0
    ? 'No pending invites'
    : `${pending} pending ${pending === 1 ? 'invite' : 'invites'}`
}

function roleSummary(data?: RoleListResponse) {
  if (!data) return ''

  const custom = data.roles.filter((role) => !role.is_system).length
  return `${custom} custom ${custom === 1 ? 'role' : 'roles'}`
}

function applicationSummary(data?: ApplicationListResponse) {
  if (!data) return ''

  const active = data.applications.filter((application) => application.status === 'active').length
  return `${active} active`
}

function itemCountLabel(count: number) {
  return `${count} ${count === 1 ? 'item' : 'items'} to review`
}

function authenticationLabel(level: CurrentUser['authentication_level']) {
  if (level === 'mfa') return 'Password and MFA'
  if (level === 'upstream') return 'Upstream identity provider'
  return 'Password'
}

function formatSessionExpiry(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}

function formatActivityTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
  }).format(new Date(value))
}
