import { zodResolver } from '@hookform/resolvers/zod'
import { Pencil, Plus, Save } from 'lucide-react'
import { useState } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'
import type { PermissionCatalogEntry, Role } from '@/api/roles'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { useCreateRole, useUpdateRole } from '@/roles/queries'

const roleSchema = z.object({
  name: z.string().trim().min(1, 'Enter a role name').max(100, 'Use 100 characters or fewer'),
  description: z.string().trim().max(300, 'Use 300 characters or fewer'),
  permissions: z.array(z.string()),
})

type RoleForm = z.infer<typeof roleSchema>

export function RoleEditorSheet({
  catalog,
  role,
}: {
  catalog: PermissionCatalogEntry[]
  role?: Role
}) {
  const [open, setOpen] = useState(false)
  const createRole = useCreateRole()
  const updateRole = useUpdateRole()
  const editing = role !== undefined

  const {
    control,
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<RoleForm>({
    resolver: zodResolver(roleSchema),
    defaultValues: roleDefaults(role),
  })

  const selectedPermissions = useWatch({
    control,
    name: 'permissions',
  })
  const pending = createRole.isPending || updateRole.isPending
  const requestError = createRole.error ?? updateRole.error

  function changeOpen(nextOpen: boolean) {
    setOpen(nextOpen)

    if (nextOpen) {
      reset(roleDefaults(role))
      return
    }

    createRole.reset()
    updateRole.reset()
    reset(roleDefaults(role))
  }

  function togglePermission(permission: string, selected: boolean) {
    const nextPermissions = selected
      ? [...selectedPermissions, permission]
      : selectedPermissions.filter((value) => value !== permission)

    setValue('permissions', nextPermissions, {
      shouldDirty: true,
      shouldValidate: true,
    })
  }

  const submit = handleSubmit(async (form) => {
    try {
      if (role) {
        await updateRole.mutateAsync({
          roleId: role.role_id,
          input: form,
        })

        toast.success('Role updated', {
          description: `${form.name} now has the selected permissions.`,
        })
      } else {
        await createRole.mutateAsync(form)

        toast.success('Role created', {
          description: `${form.name} is ready to assign to members.`,
        })
      }

      changeOpen(false)
    } catch {
      // The request error is rendered inside the sheet.
    }
  })

  return (
    <Sheet open={open} onOpenChange={changeOpen}>
      <SheetTrigger asChild>
        <Button type="button" variant={editing ? 'outline' : 'default'} className="rounded-lg">
          {editing ? <Pencil aria-hidden="true" /> : <Plus aria-hidden="true" />}
          {editing ? 'Edit role' : 'Create role'}
        </Button>
      </SheetTrigger>

      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader className="border-b border-border">
          <SheetTitle className="text-xl">
            {editing ? 'Edit custom role' : 'Create role'}
          </SheetTitle>

          <SheetDescription>
            {editing
              ? 'Change the role details and the permissions granted to its members.'
              : 'Define a reusable set of permissions for members in this organization.'}
          </SheetDescription>
        </SheetHeader>

        <form onSubmit={submit} noValidate className="flex min-h-0 flex-1 flex-col">
          <div className="flex-1 space-y-7 overflow-y-auto px-6 py-6">
            <RequestError error={requestError} />

            <FieldGroup className="gap-5">
              <Field data-invalid={Boolean(errors.name) || undefined}>
                <FieldLabel htmlFor={editing ? `role-name-${role.role_id}` : 'new-role-name'}>
                  Role name
                </FieldLabel>

                <Input
                  {...register('name')}
                  id={editing ? `role-name-${role.role_id}` : 'new-role-name'}
                  autoFocus
                  autoComplete="off"
                  maxLength={100}
                  aria-invalid={Boolean(errors.name)}
                  placeholder="Support administrator"
                  className="h-11 rounded-lg"
                />

                <FieldError errors={[errors.name]} />
              </Field>

              <Field data-invalid={Boolean(errors.description) || undefined}>
                <FieldLabel
                  htmlFor={editing ? `role-description-${role.role_id}` : 'new-role-description'}
                >
                  Description
                </FieldLabel>

                <Textarea
                  {...register('description')}
                  id={editing ? `role-description-${role.role_id}` : 'new-role-description'}
                  maxLength={300}
                  aria-invalid={Boolean(errors.description)}
                  placeholder="Describe what this role is responsible for."
                  className="min-h-24 resize-y rounded-lg bg-card"
                />

                <FieldDescription>
                  Optional. Visible to organization administrators.
                </FieldDescription>
                <FieldError errors={[errors.description]} />
              </Field>
            </FieldGroup>

            <FieldSet>
              <FieldLegend>Permissions</FieldLegend>

              <FieldDescription>
                Members receive every permission selected for this role.
              </FieldDescription>

              <div className="space-y-3">
                {catalog.map((permission) => {
                  const checkboxID = `${role?.role_id ?? 'new-role'}-${permission.permission}`
                  const checked = selectedPermissions.includes(permission.permission)

                  return (
                    <label
                      key={permission.permission}
                      htmlFor={checkboxID}
                      className="flex cursor-pointer items-start gap-3 rounded-xl border border-border bg-card p-4 transition-colors hover:border-primary/30 hover:bg-primary/[0.025]"
                    >
                      <Checkbox
                        id={checkboxID}
                        checked={checked}
                        onCheckedChange={(value) =>
                          togglePermission(permission.permission, value === true)
                        }
                        className="mt-0.5"
                      />

                      <span className="min-w-0">
                        <span className="block text-sm font-semibold">{permission.name}</span>

                        <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                          {permission.description}
                        </span>

                        <span className="mt-2 block font-mono text-[0.65rem] text-muted-foreground">
                          {permission.permission}
                        </span>
                      </span>
                    </label>
                  )
                })}
              </div>
            </FieldSet>
          </div>

          <SheetFooter className="border-t border-border">
            <SheetClose asChild>
              <Button type="button" variant="outline" disabled={pending} className="rounded-lg">
                Cancel
              </Button>
            </SheetClose>

            <Button type="submit" disabled={pending} className="rounded-lg">
              {pending ? (
                <>
                  <Spinner />
                  {editing ? 'Saving role' : 'Creating role'}
                </>
              ) : (
                <>
                  <Save aria-hidden="true" />
                  {editing ? 'Save changes' : 'Create role'}
                </>
              )}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  )
}

function roleDefaults(role?: Role): RoleForm {
  return {
    name: role?.name ?? '',
    description: role?.description ?? '',
    permissions: role?.permissions ?? [],
  }
}
