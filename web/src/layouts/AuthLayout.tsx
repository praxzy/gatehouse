import { Fingerprint, KeyRound, Network } from 'lucide-react'
import { Link, Outlet } from 'react-router-dom'
import { GatehouseBrand } from '@/components/GatehouseBrand'

const principles = [
  {
    icon: Fingerprint,
    label: 'Authentication',
  },
  {
    icon: Network,
    label: 'Organizations',
  },
  {
    icon: KeyRound,
    label: 'OIDC applications',
  },
]

export function AuthLayout() {
  return (
    <main className="grid min-h-svh bg-background lg:grid-cols-[minmax(0,1.08fr)_minmax(30rem,0.92fr)]">
      <section className="relative hidden min-h-svh overflow-hidden bg-gatehouse-forest px-12 py-10 text-white lg:flex lg:flex-col xl:px-16 xl:py-12">
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.08]"
          aria-hidden="true"
          style={{
            backgroundImage:
              'linear-gradient(rgba(255,255,255,.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.6) 1px, transparent 1px)',
            backgroundSize: '56px 56px',
          }}
        />

        <div
          className="pointer-events-none absolute top-1/2 -right-24 h-[78%] w-[58%] -translate-y-1/2 rounded-t-[18rem] border border-white/10"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute top-1/2 -right-8 h-[62%] w-[42%] -translate-y-1/2 rounded-t-[14rem] border border-white/10"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute right-[12%] bottom-0 h-[48%] w-px bg-white/10"
          aria-hidden="true"
        />

        <Link to="/" className="relative z-10 w-fit no-underline" aria-label="Gatehouse home">
          <GatehouseBrand inverse />
        </Link>

        <div className="relative z-10 my-auto max-w-xl py-16">
          <div className="mb-7 flex items-center gap-3 text-xs font-semibold tracking-[0.16em] text-emerald-200 uppercase">
            <span className="h-px w-9 bg-gatehouse-brass" />
            Identity administration
          </div>

          <h1 className="max-w-lg font-heading text-5xl leading-[0.98] font-medium tracking-[-0.035em] text-balance xl:text-6xl">
            Identity and access in one place.
          </h1>

          <p className="mt-7 max-w-lg text-base leading-7 text-white/64">
            Manage authentication, access, and applications for your organization.
          </p>
        </div>

        <div className="relative z-10 grid grid-cols-3 gap-3">
          {principles.map(({ icon: Icon, label }) => (
            <div key={label} className="border-t border-white/12 pt-4">
              <Icon
                className="mb-3 text-emerald-200"
                size={18}
                strokeWidth={1.7}
                aria-hidden="true"
              />
              <p className="max-w-32 text-xs leading-5 text-white/55">{label}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="relative flex min-h-svh flex-col">
        <header className="flex items-center justify-between px-6 py-6 lg:hidden">
          <Link to="/" className="no-underline" aria-label="Gatehouse home">
            <GatehouseBrand />
          </Link>
        </header>

        <div className="flex flex-1 items-center justify-center px-6 py-10 sm:px-10 lg:px-14">
          <div className="w-full max-w-[27rem]">
            <Outlet />
          </div>
        </div>

        <footer className="flex items-center justify-between border-t border-border/70 px-6 py-4 text-xs text-muted-foreground sm:px-10 lg:px-14">
          <span>Gatehouse Identity Platform</span>
        </footer>
      </section>
    </main>
  )
}
