import { KeyRound, LockKeyhole, ShieldCheck } from 'lucide-react'
import type { PermissionCatalogEntry, Role } from '@/api/roles'
import { useCurrentUser } from '@/auth/currentUser'
import { hasPermission, permissions } from '@/auth/permissions'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'
import { RoleEditorSheet } from '@/roles/RoleEditorSheet'
import { useRoles } from '@/roles/queries'

export function RolesPage() {
  const roles = useRoles()
  const currentUser = useCurrentUser()

  const canManageRoles = currentUser.data
    ? hasPermission(currentUser.data.permissions, permissions.roleManage)
    : false

  if (roles.isPending) {
    return (
      <PageContainer>
        <div
          className="flex min-h-80 items-center justify-center gap-3 text-sm font-medium text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Loading roles
        </div>
      </PageContainer>
    )
  }

  if (roles.isError) {
    return (
      <PageContainer>
        <Surface className="mx-auto max-w-xl p-6">
          <h1 className="font-heading text-2xl font-medium">Roles couldn’t be loaded</h1>

          <div className="mt-4">
            <RequestError error={roles.error} />
          </div>

          <Button
            type="button"
            variant="outline"
            onClick={() => roles.refetch()}
            className="mt-5 rounded-lg"
          >
            Try again
          </Button>
        </Surface>
      </PageContainer>
    )
  }

  const customRoleCount = roles.data.roles.filter((role) => !role.is_system).length

  return (
    <PageContainer>
      <header className="motion-enter flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-[0.67rem] tracking-[0.14em] text-muted-foreground uppercase">
            Access control
          </p>

          <h1 className="mt-2 font-heading text-4xl font-medium tracking-[-0.035em]">Roles</h1>

          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            {roles.data.roles.length} {roles.data.roles.length === 1 ? 'role' : 'roles'}, including{' '}
            {customRoleCount} custom.
          </p>
        </div>

        {canManageRoles && <RoleEditorSheet catalog={roles.data.permissions} />}
      </header>

      <div className="motion-enter motion-enter-delay-1 mt-8 grid gap-4 xl:grid-cols-2">
        {roles.data.roles.map((role) => (
          <RoleCard
            key={role.role_id}
            role={role}
            catalog={roles.data.permissions}
            canManage={canManageRoles}
          />
        ))}
      </div>
    </PageContainer>
  )
}

function RoleCard({
  role,
  catalog,
  canManage,
}: {
  role: Role
  catalog: PermissionCatalogEntry[]
  canManage: boolean
}) {
  const grantedPermissions = catalog.filter((permission) =>
    role.permissions.includes(permission.permission),
  )

  return (
    <Surface className="flex min-h-64 flex-col p-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <div
            className={
              role.is_system
                ? 'grid size-10 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary'
                : 'grid size-10 shrink-0 place-items-center rounded-lg bg-gatehouse-brass/10 text-gatehouse-brass'
            }
            aria-hidden="true"
          >
            {role.is_system ? <LockKeyhole size={18} /> : <KeyRound size={18} />}
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate text-base font-semibold">{role.name}</h2>

              {role.is_system && (
                <span className="rounded-full bg-primary/8 px-2 py-0.5 text-[0.62rem] font-semibold text-primary">
                  Built in
                </span>
              )}
            </div>

            <p className="mt-1 text-xs text-muted-foreground">
              {role.permissions.length}{' '}
              {role.permissions.length === 1 ? 'permission' : 'permissions'}
            </p>
          </div>
        </div>

        {!role.is_system && canManage && <RoleEditorSheet catalog={catalog} role={role} />}
      </div>

      <p className="mt-5 text-sm leading-6 text-muted-foreground">
        {role.description || 'No description provided.'}
      </p>

      <div className="mt-6 border-t border-border pt-5">
        <p className="text-[0.65rem] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
          Permissions
        </p>

        {grantedPermissions.length > 0 ? (
          <ul className="mt-3 flex flex-wrap gap-2">
            {grantedPermissions.map((permission) => (
              <li
                key={permission.permission}
                className="inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/45 px-2.5 py-1 text-xs font-medium"
                title={permission.description}
              >
                <ShieldCheck size={13} className="text-primary" aria-hidden="true" />
                {permission.name}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-3 text-sm text-muted-foreground">No access granted.</p>
        )}
      </div>
    </Surface>
  )
}

function PageContainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-376 px-5 py-7 sm:px-7 lg:px-10 lg:py-9">{children}</div>
  )
}
