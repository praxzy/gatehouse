import {
  AppWindow,
  FileClock,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Users,
  X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Suspense, useState } from 'react'
import type { MouseEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { toast } from 'sonner'
import { logout } from '@/api/auth'
import { APIError } from '@/api/client'
import { useCurrentUser } from '@/auth/currentUser'
import { GatehouseBrand } from '@/components/GatehouseBrand'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { Spinner } from '@/components/ui/spinner'
import { cn } from '@/lib/utils'
import { ErrorReference } from '@/components/ErrorReference'
import type { Permission } from '@/auth/permissions'
import { hasPermission, permissions } from '@/auth/permissions'

const sidebarPreferenceKey = 'gatehouse:admin-sidebar-collapsed'

const sidebarTextTransition =
  'min-w-0 overflow-hidden whitespace-nowrap transition-opacity duration-150 motion-reduce:transition-none'

type NavigationItem = {
  label: string
  icon: LucideIcon
  to?: string
  requires?: Permission
}

const navigation: NavigationItem[] = [
  {
    label: 'Overview',
    icon: LayoutDashboard,
    to: '/app',
  },
  {
    label: 'Directory',
    icon: Users,
    to: '/app/members',
    requires: permissions.memberRead,
  },
  {
    label: 'Roles and access',
    icon: KeyRound,
    to: '/app/roles',
    requires: permissions.roleRead,
  },
  {
    label: 'Applications',
    icon: AppWindow,
  },
  {
    label: 'Audit activity',
    icon: FileClock,
  },
]

export function AdminLayout() {
  const currentUser = useCurrentUser()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readSidebarPreference)
  const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false)

  function toggleSidebar() {
    setSidebarCollapsed((collapsed) => {
      const nextValue = !collapsed
      writeSidebarPreference(nextValue)
      return nextValue
    })
  }

  function expandFromCollapsedRail(event: MouseEvent<HTMLElement>) {
    if (!sidebarCollapsed) {
      return
    }

    const target = event.target

    if (
      target instanceof Element &&
      target.closest(
        'a, button, input, select, textarea, [role="button"], [data-sidebar-keep-action]',
      )
    ) {
      return
    }

    setSidebarCollapsed(false)
    writeSidebarPreference(false)
  }

  function finishLogout() {
    queryClient.clear()
    navigate('/login', { replace: true })
  }

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSuccess: finishLogout,
    onError: (error) => {
      if (error instanceof APIError && error.status === 401) {
        finishLogout()
        return
      }

      toast.error('Could not sign out', {
        description: logoutErrorDescription(error),
      })
    },
  })

  if (!currentUser.data) {
    return null
  }

  const user = currentUser.data

  const visibleNavigation = navigation.filter(
    (item) => !item.requires || hasPermission(user.permissions, item.requires),
  )

  return (
    <div
      className={cn(
        'min-h-svh bg-background motion-reduce:transition-none lg:grid lg:transition-[grid-template-columns] lg:[transition-duration:var(--motion-duration-standard)] lg:[transition-timing-function:var(--motion-ease-standard)]',
        sidebarCollapsed
          ? 'lg:grid-cols-[4.75rem_minmax(0,1fr)]'
          : 'lg:grid-cols-[18rem_minmax(0,1fr)]',
      )}
    >
      <aside
        id="admin-sidebar"
        onClick={expandFromCollapsedRail}
        className={cn(
          'group/sidebar sticky top-0 z-10 hidden h-svh flex-col self-start overflow-hidden border-r border-sidebar-border bg-sidebar text-sidebar-foreground lg:flex',
          sidebarCollapsed && 'cursor-ew-resize',
        )}
      >
        <div className="relative flex min-h-[5.0625rem] w-full shrink-0 items-center overflow-hidden border-b border-sidebar-border px-[1.125rem] py-5">
          <NavLink to="/app" aria-label="Gatehouse admin overview">
            <GatehouseBrand
              inverse
              showDescriptor={false}
              className={cn(
                'min-w-max [&>span:last-child]:transition-opacity [&>span:last-child]:duration-150 [&>span:last-child]:motion-reduce:transition-none',
                sidebarCollapsed
                  ? 'group-hover/sidebar:opacity-0 [&>span:last-child]:invisible [&>span:last-child]:opacity-0'
                  : '[&>span:last-child]:visible [&>span:last-child]:opacity-100 [&>span:last-child]:delay-150',
              )}
            />
          </NavLink>

          <button
            type="button"
            onClick={toggleSidebar}
            data-sidebar-keep-action
            aria-controls="admin-sidebar"
            aria-expanded="false"
            aria-label="Expand sidebar"
            title="Expand sidebar"
            className={cn(
              'pointer-events-none absolute top-5 left-4.5 grid size-10 cursor-ew-resize! place-items-center border-0 bg-transparent p-0 text-sidebar-accent-foreground opacity-0 outline-none hover:bg-transparent hover:text-sidebar-accent-foreground focus-visible:pointer-events-auto focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-sidebar-ring/50',
              sidebarCollapsed
                ? 'visible group-hover/sidebar:pointer-events-auto group-hover/sidebar:opacity-100'
                : 'invisible',
            )}
          >
            <PanelLeftOpen className="size-4" aria-hidden="true" />
          </button>

          <button
            type="button"
            onClick={toggleSidebar}
            data-sidebar-keep-action
            aria-controls="admin-sidebar"
            aria-expanded="true"
            aria-label="Collapse sidebar"
            title="Collapse sidebar"
            className={cn(
              'absolute top-5 right-[1.125rem] grid size-10 cursor-ew-resize! place-items-center rounded-lg border-0 bg-transparent p-0 text-sidebar-accent-foreground transition-colors duration-150 outline-none hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:ring-sidebar-ring/50 motion-reduce:transition-none',
              sidebarCollapsed ? 'pointer-events-none invisible opacity-0' : 'visible opacity-100',
            )}
          >
            <PanelLeftClose className="size-4" aria-hidden="true" />
          </button>
        </div>

        <div className="w-full shrink-0 py-4">
          <div
            className={cn(
              'mx-2 grid min-h-14 grid-cols-[3.75rem_minmax(0,1fr)] items-center rounded-lg border border-sidebar-border bg-sidebar-accent/50',
            )}
            title={sidebarCollapsed ? `${user.tenant_name} (${user.tenant_slug})` : undefined}
          >
            <div
              className="grid size-8 place-items-center justify-self-center rounded-md bg-sidebar-primary/12 text-xs font-semibold text-sidebar-primary"
              aria-hidden="true"
            >
              {initials(user.tenant_name)}
            </div>

            <div
              className={cn(
                sidebarTextTransition,
                sidebarCollapsed ? 'invisible opacity-0' : 'visible pr-3 opacity-100 delay-150',
              )}
            >
              <p className="truncate text-sm font-semibold text-sidebar-accent-foreground">
                {user.tenant_name}
              </p>
              <p className="truncate font-mono text-[0.67rem] text-sidebar-foreground/50">
                {user.tenant_slug}
              </p>
            </div>
          </div>
        </div>

        <nav
          aria-label="Administration"
          className={cn('min-h-0 w-full flex-1 overflow-x-hidden overflow-y-auto py-2')}
        >
          <p
            className={cn(
              'mb-2 h-4 pl-[4.25rem] text-[0.65rem] font-semibold tracking-[0.14em] text-sidebar-foreground/40 uppercase',
              sidebarTextTransition,
              'duration-200 ease-in-out',
              sidebarCollapsed ? 'invisible opacity-0' : 'visible opacity-100 delay-100',
            )}
          >
            Workspace
          </p>

          <ul className="space-y-1">
            {visibleNavigation.map((item) => (
              <li key={item.label}>
                {item.to ? (
                  <NavLink
                    to={item.to}
                    end
                    aria-label={sidebarCollapsed ? item.label : undefined}
                    title={sidebarCollapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      [
                        'mx-2 grid h-10 grid-cols-[3.75rem_minmax(0,1fr)] items-center rounded-md text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                          : 'text-sidebar-foreground/65 hover:bg-sidebar-accent/55 hover:text-sidebar-accent-foreground',
                      ].join(' ')
                    }
                  >
                    <item.icon
                      size={17}
                      strokeWidth={1.8}
                      className="justify-self-center"
                      aria-hidden="true"
                    />
                    <span
                      className={cn(
                        sidebarTextTransition,
                        sidebarCollapsed
                          ? 'invisible opacity-0'
                          : 'visible pr-3 opacity-100 delay-150',
                      )}
                    >
                      {item.label}
                    </span>
                  </NavLink>
                ) : (
                  <div
                    aria-disabled="true"
                    aria-label={sidebarCollapsed ? `${item.label}, coming soon` : undefined}
                    title={sidebarCollapsed ? `${item.label} — Soon` : undefined}
                    className={cn(
                      'mx-2 grid h-10 grid-cols-[3.75rem_minmax(0,1fr)] items-center rounded-md text-sm text-sidebar-foreground/35',
                    )}
                  >
                    <item.icon
                      size={17}
                      strokeWidth={1.8}
                      className="justify-self-center"
                      aria-hidden="true"
                    />
                    <span
                      className={cn(
                        'flex items-center pr-3',
                        sidebarTextTransition,
                        sidebarCollapsed ? 'invisible opacity-0' : 'visible opacity-100 delay-150',
                      )}
                    >
                      <span className="truncate">{item.label}</span>
                      <span className="ml-auto text-[0.6rem] font-semibold tracking-wider uppercase">
                        Soon
                      </span>
                    </span>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </nav>

        <div className={cn('w-full shrink-0 border-t border-sidebar-border py-3')}>
          <div
            className={cn('mx-2 mb-2 grid min-h-10 grid-cols-[3.75rem_minmax(0,1fr)] items-center')}
            title={sidebarCollapsed ? `${user.display_name} (${user.email})` : undefined}
          >
            <div className="grid size-8 shrink-0 place-items-center justify-self-center rounded-md bg-sidebar-accent text-xs font-semibold text-sidebar-accent-foreground">
              {initials(user.display_name)}
            </div>

            <div
              className={cn(
                sidebarTextTransition,
                sidebarCollapsed ? 'invisible opacity-0' : 'visible pr-3 opacity-100 delay-150',
              )}
            >
              <p className="truncate text-sm font-semibold">{user.display_name}</p>
              <p className="truncate text-xs text-sidebar-foreground/45">{user.email}</p>
            </div>
          </div>

          <Button
            type="button"
            variant="ghost"
            disabled={logoutMutation.isPending}
            onClick={() => logoutMutation.mutate()}
            data-sidebar-keep-action
            aria-label="Sign out"
            title={sidebarCollapsed ? 'Sign out' : undefined}
            className={cn(
              'relative mx-2 h-9 w-[calc(100%-1rem)] justify-start rounded-md p-0 text-sidebar-foreground/65 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
            )}
          >
            <LogOut className="absolute left-[1.375rem]" aria-hidden="true" />
            <span
              className={cn(
                'ml-[3.75rem] text-left',
                sidebarTextTransition,
                sidebarCollapsed ? 'invisible opacity-0' : 'visible pr-3 opacity-100 delay-150',
              )}
            >
              {logoutMutation.isPending ? 'Signing out' : 'Sign out'}
            </span>
          </Button>
        </div>
      </aside>

      <div className="flex min-h-svh min-w-0 flex-col">
        <header className="flex h-16 items-center justify-between border-b border-border bg-card/70 px-5 backdrop-blur-sm sm:px-7 lg:hidden">
          <NavLink to="/app" aria-label="Gatehouse admin overview">
            <GatehouseBrand compact />
          </NavLink>

          <Sheet open={mobileNavigationOpen} onOpenChange={setMobileNavigationOpen}>
            <SheetTrigger asChild>
              <Button
                type="button"
                variant="outline"
                size="icon"
                className="rounded-md"
                aria-label="Open navigation"
                title="Open navigation"
              >
                <Menu aria-hidden="true" />
              </Button>
            </SheetTrigger>

            <SheetContent
              side="left"
              showCloseButton={false}
              className="w-[min(21rem,calc(100vw-2.75rem))] max-w-none border-sidebar-border bg-sidebar p-0 text-sidebar-foreground"
            >
              <SheetTitle className="sr-only">Administration navigation</SheetTitle>
              <SheetDescription className="sr-only">
                Navigate your Gatehouse workspace and manage your account.
              </SheetDescription>

              <div className="flex min-h-[5.0625rem] shrink-0 items-center justify-between border-b border-sidebar-border px-5 py-5">
                <NavLink
                  to="/app"
                  aria-label="Gatehouse admin overview"
                  onClick={() => setMobileNavigationOpen(false)}
                >
                  <GatehouseBrand inverse showDescriptor={false} />
                </NavLink>

                <SheetClose asChild>
                  <button
                    type="button"
                    className="grid size-9 place-items-center rounded-md text-sidebar-foreground/65 transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:ring-sidebar-ring/50 focus-visible:outline-none"
                    aria-label="Close navigation"
                    title="Close navigation"
                  >
                    <X className="size-4" aria-hidden="true" />
                  </button>
                </SheetClose>
              </div>

              <div className="shrink-0 px-3 py-4">
                <div className="grid min-h-14 grid-cols-[3.5rem_minmax(0,1fr)] items-center rounded-lg border border-sidebar-border bg-sidebar-accent/50">
                  <div
                    className="grid size-8 place-items-center justify-self-center rounded-md bg-sidebar-primary/12 text-xs font-semibold text-sidebar-primary"
                    aria-hidden="true"
                  >
                    {initials(user.tenant_name)}
                  </div>

                  <div className="min-w-0 pr-3">
                    <p className="truncate text-sm font-semibold text-sidebar-accent-foreground">
                      {user.tenant_name}
                    </p>
                    <p className="truncate font-mono text-[0.67rem] text-sidebar-foreground/50">
                      {user.tenant_slug}
                    </p>
                  </div>
                </div>
              </div>

              <nav
                aria-label="Mobile administration"
                className="min-h-0 flex-1 overflow-y-auto px-3 py-2"
              >
                <p className="mb-2 px-3 text-[0.65rem] font-semibold tracking-[0.14em] text-sidebar-foreground/40 uppercase">
                  Workspace
                </p>

                <ul className="space-y-1">
                  {visibleNavigation.map((item) => (
                    <li key={item.label}>
                      {item.to ? (
                        <NavLink
                          to={item.to}
                          end
                          onClick={() => setMobileNavigationOpen(false)}
                          className={({ isActive }) =>
                            cn(
                              'flex h-11 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors',
                              isActive
                                ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                                : 'text-sidebar-foreground/65 hover:bg-sidebar-accent/55 hover:text-sidebar-accent-foreground',
                            )
                          }
                        >
                          <item.icon size={17} strokeWidth={1.8} aria-hidden="true" />
                          {item.label}
                        </NavLink>
                      ) : (
                        <div
                          aria-disabled="true"
                          className="flex h-11 items-center gap-3 rounded-md px-3 text-sm text-sidebar-foreground/35"
                        >
                          <item.icon size={17} strokeWidth={1.8} aria-hidden="true" />
                          <span>{item.label}</span>
                          <span className="ml-auto text-[0.6rem] font-semibold tracking-wider uppercase">
                            Soon
                          </span>
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </nav>

              <div className="shrink-0 border-t border-sidebar-border p-3">
                <div className="mb-2 grid min-h-11 grid-cols-[3.5rem_minmax(0,1fr)] items-center">
                  <div className="grid size-8 place-items-center justify-self-center rounded-md bg-sidebar-accent text-xs font-semibold text-sidebar-accent-foreground">
                    {initials(user.display_name)}
                  </div>

                  <div className="min-w-0 pr-3">
                    <p className="truncate text-sm font-semibold">{user.display_name}</p>
                    <p className="truncate text-xs text-sidebar-foreground/45">{user.email}</p>
                  </div>
                </div>

                <Button
                  type="button"
                  variant="ghost"
                  disabled={logoutMutation.isPending}
                  onClick={() => logoutMutation.mutate()}
                  className="h-10 w-full justify-start gap-3 rounded-md px-4 text-sidebar-foreground/65 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
                >
                  <LogOut aria-hidden="true" />
                  {logoutMutation.isPending ? 'Signing out' : 'Sign out'}
                </Button>
              </div>
            </SheetContent>
          </Sheet>
        </header>

        <main className="min-w-0 flex-1">
          <Suspense fallback={<AdminPageLoading />}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  )
}

function AdminPageLoading() {
  return (
    <div
      aria-busy="true"
      aria-live="polite"
      className="grid min-h-[calc(100svh-4rem)] place-items-center lg:min-h-svh"
    >
      <div className="flex items-center gap-3 text-sm font-medium text-muted-foreground">
        <Spinner />
        Loading page
      </div>
    </div>
  )
}

function initials(displayName: string) {
  const parts = displayName.trim().split(/\s+/)

  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('')
}

function readSidebarPreference() {
  if (typeof window === 'undefined') {
    return false
  }

  try {
    return window.localStorage.getItem(sidebarPreferenceKey) === 'true'
  } catch {
    return false
  }
}

function writeSidebarPreference(collapsed: boolean) {
  try {
    window.localStorage.setItem(sidebarPreferenceKey, String(collapsed))
  } catch {
    // The sidebar still works when storage is unavailable.
  }
}

function logoutErrorDescription(error: unknown) {
  if (!(error instanceof APIError)) {
    return <p>Please try again.</p>
  }

  return (
    <div>
      <p>{error.message}</p>
      <ErrorReference requestId={error.requestId} />
    </div>
  )
}
