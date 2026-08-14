import {
  AppWindow,
  ArrowUpRight,
  Check,
  Fingerprint,
  KeyRound,
  ListChecks,
  Network,
  ShieldCheck,
  Users,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { useCurrentUser } from '@/auth/currentUser'
import { Surface } from '@/components/ui/surface'
import { usePointerTilt } from '@/hooks/usePointerTilt'
import { cn } from '@/lib/utils'

const controlSurfaces = [
  {
    icon: Users,
    number: '01',
    title: 'Identity directory',
    description: 'Users and memberships.',
    tone: 'default',
  },
  {
    icon: KeyRound,
    number: '02',
    title: 'Access control',
    description: 'Roles and permissions.',
    tone: 'primary',
  },
  {
    icon: AppWindow,
    number: '03',
    title: 'Applications',
    description: 'OIDC client configuration.',
    tone: 'brass',
  },
] as const

const controlSurfaceMotion = [
  'motion-enter motion-enter-delay-3',
  'motion-enter motion-enter-delay-4',
  'motion-enter motion-enter-delay-5',
] as const

export function DashboardPage() {
  const currentUser = useCurrentUser()

  if (!currentUser.data) {
    return null
  }

  const user = currentUser.data

  return (
    <div className="mx-auto w-full max-w-[94rem] px-5 py-7 sm:px-7 lg:px-10 lg:py-9">
      <section className="grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(20rem,0.7fr)]">
        <BoundaryHero
          tenantName={user.tenant_name}
          tenantSlug={user.tenant_slug}
          mfaEnrolled={user.mfa_enrolled}
        />

        <SecurityPosture mfaEnrolled={user.mfa_enrolled} />
      </section>

      <section className="mt-9">
        <div className="motion-enter motion-enter-delay-2 mb-4 flex items-end justify-between">
          <div>
            <h2 className="mt-1 font-heading text-2xl font-medium tracking-tight">
              Administration
            </h2>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-12">
          {controlSurfaces.map((surface, index) => (
            <ControlSurface
              key={surface.title}
              {...surface}
              className={cn(
                index === 0 ? 'md:col-span-5' : index === 1 ? 'md:col-span-4' : 'md:col-span-3',
                controlSurfaceMotion[index],
              )}
            />
          ))}
        </div>
      </section>

      <section className="mt-9 grid gap-5 xl:grid-cols-[minmax(0,1fr)_23rem]">
        <BoundaryActivity />

        <OrganizationSetup mfaEnrolled={user.mfa_enrolled} />
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

function SecurityPosture({ mfaEnrolled }: { mfaEnrolled: boolean }) {
  const enabledControls = mfaEnrolled ? 3 : 2
  const score = Math.round((enabledControls / 3) * 100)

  return (
    <Surface className="motion-enter motion-enter-delay-1 flex flex-col p-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="mt-2 font-heading text-2xl font-medium tracking-[-0.025em]">
            Security posture
          </h2>
        </div>

        <SecurityScore score={score} enabled={enabledControls} />
      </div>

      <div className="mt-7 divide-y divide-border">
        <SecurityControl
          icon={Network}
          title="Tenant isolation"
          description="Tenant-scoped access."
          active
        />

        <SecurityControl
          icon={ShieldCheck}
          title="Sessions"
          description="Server-side revocation."
          active
        />

        <SecurityControl
          icon={Fingerprint}
          title="Administrator MFA"
          description={mfaEnrolled ? 'Enabled for your account.' : 'Not enabled.'}
          active={mfaEnrolled}
        />
      </div>

      {!mfaEnrolled && (
        <Link
          to="/mfa/enroll"
          className="mt-auto flex items-center justify-between border-t border-border pt-5 text-sm font-semibold text-primary"
        >
          Set up MFA
          <ArrowUpRight size={16} aria-hidden="true" />
        </Link>
      )}
    </Surface>
  )
}

function SecurityScore({ score, enabled }: { score: number; enabled: number }) {
  return (
    <div
      className="relative grid size-16 place-items-center"
      aria-label={`${enabled} of 3 security controls active`}
    >
      <svg viewBox="0 0 44 44" className="absolute inset-0 size-full -rotate-90" aria-hidden="true">
        <circle
          cx="22"
          cy="22"
          r="18"
          pathLength="100"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          className="text-muted"
        />
        <circle
          cx="22"
          cy="22"
          r="18"
          pathLength="100"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray="100"
          className="motion-score-ring text-primary"
          style={
            {
              '--score-offset': 100 - score,
            } as CSSProperties
          }
        />
      </svg>

      <div className="text-center">
        <p className="text-sm leading-none font-bold">{enabled}/3</p>
        <p className="mt-1 text-[0.55rem] font-semibold tracking-wide text-muted-foreground uppercase">
          Active
        </p>
      </div>
    </div>
  )
}

function SecurityControl({
  icon: Icon,
  title,
  description,
  active,
}: {
  icon: LucideIcon
  title: string
  description: string
  active: boolean
}) {
  return (
    <div className="grid grid-cols-[auto_1fr_auto] items-center gap-3 py-4 first:pt-0 last:pb-0">
      <div className="grid size-8 place-items-center rounded-md bg-muted text-foreground">
        <Icon size={15} aria-hidden="true" />
      </div>

      <div>
        <p className="text-sm font-semibold">{title}</p>
        <p className="mt-0.5 text-xs leading-5 text-muted-foreground">{description}</p>
      </div>

      <span
        className={
          active
            ? 'grid size-5 place-items-center rounded-full bg-primary/10 text-primary'
            : 'size-2 rounded-full bg-gatehouse-brass'
        }
      >
        {active && <Check size={12} aria-hidden="true" />}
      </span>
    </div>
  )
}

type ControlSurfaceProps = {
  icon: LucideIcon
  number: string
  title: string
  description: string
  tone: 'default' | 'primary' | 'brass'
  className?: string
}

function ControlSurface({
  icon: Icon,
  number,
  title,
  description,
  tone,
  className = '',
}: ControlSurfaceProps) {
  return (
    <Surface tone={tone} className={cn('min-h-48 p-5', className)}>
      <span className="absolute top-4 right-4 font-mono text-[0.65rem] text-muted-foreground/55">
        {number}
      </span>

      <div className="grid size-10 place-items-center rounded-md border border-current/10 bg-background/60 text-primary">
        <Icon size={18} aria-hidden="true" />
      </div>

      <div className="mt-8">
        <h3 className="font-heading text-xl font-medium tracking-[-0.02em]">{title}</h3>
        <p className="mt-2 max-w-xs text-xs leading-5 text-muted-foreground">{description}</p>
      </div>
    </Surface>
  )
}

function BoundaryActivity() {
  return (
    <Surface className="motion-enter motion-enter-delay-4">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <p className="text-sm font-semibold">Recent activity</p>
        </div>
      </div>

      <div className="grid min-h-56 place-items-center px-6 py-10 text-center">
        <div className="max-w-sm">
          <h3 className="mt-5 font-heading text-xl font-medium">No activity yet</h3>
        </div>
      </div>
    </Surface>
  )
}

function OrganizationSetup({ mfaEnrolled }: { mfaEnrolled: boolean }) {
  return (
    <Surface className="motion-enter motion-enter-delay-5 p-5">
      <div className="flex items-center gap-3">
        <div className="grid size-9 place-items-center rounded-md bg-primary/10 text-primary">
          <ListChecks size={17} aria-hidden="true" />
        </div>

        <div>
          <p className="text-sm font-semibold">Organization setup</p>
        </div>
      </div>

      <ol className="mt-6 space-y-5">
        <SetupStep number="01" title="Organization created" complete />
        <SetupStep number="02" title="Administrator account" complete />
        <SetupStep number="03" title="MFA enrollment" complete={mfaEnrolled} />
        <SetupStep number="04" title="First OIDC application" complete={false} final />
      </ol>
    </Surface>
  )
}

function SetupStep({
  number,
  title,
  complete,
  final = false,
}: {
  number: string
  title: string
  complete: boolean
  final?: boolean
}) {
  return (
    <li className="relative grid grid-cols-[auto_1fr_auto] items-center gap-3">
      {!final && (
        <span className="absolute top-6 left-[0.7rem] h-5 w-px bg-border" aria-hidden="true" />
      )}

      <span
        className={[
          'relative z-10 grid size-6 place-items-center rounded-full text-[0.58rem] font-bold',
          complete
            ? 'bg-primary text-primary-foreground'
            : 'border border-border bg-background text-muted-foreground',
        ].join(' ')}
      >
        {complete ? <Check size={12} aria-hidden="true" /> : number}
      </span>

      <span className={complete ? 'text-sm font-medium' : 'text-sm text-muted-foreground'}>
        {title}
      </span>

      <span className="text-[0.62rem] font-semibold tracking-wide text-muted-foreground uppercase">
        {complete ? 'Complete' : 'Next'}
      </span>
    </li>
  )
}
