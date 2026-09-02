import { Pencil, Save } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import type { ApplicationAccessMode, ApplicationDetail } from '@/api/applications'
import type { Role } from '@/api/roles'
import { useUpdateApplicationAccessPolicy } from '@/applications/queries'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { FieldDescription, FieldError, FieldLegend, FieldSet } from '@/components/ui/field'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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

export function ApplicationAccessPolicySheet({
  application,
  roles,
}: {
  application: ApplicationDetail
  roles: Role[]
}) {
  const [open, setOpen] = useState(false)
  const [accessMode, setAccessMode] = useState<ApplicationAccessMode>(application.access_mode)
  const [selectedRoleIDs, setSelectedRoleIDs] = useState(
    application.allowed_roles.map((role) => role.role_id),
  )

  const updatePolicy = useUpdateApplicationAccessPolicy(application.application_id)
  const selectionRequired = accessMode === 'allowed_roles' && selectedRoleIDs.length === 0

  function changeOpen(nextOpen: boolean) {
    setOpen(nextOpen)
    setAccessMode(application.access_mode)
    setSelectedRoleIDs(application.allowed_roles.map((role) => role.role_id))
    updatePolicy.reset()
  }

  function changeAccessMode(value: ApplicationAccessMode) {
    setAccessMode(value)

    if (value === 'all_active_members') {
      setSelectedRoleIDs([])
    }
  }

  function toggleRole(roleID: string, selected: boolean) {
    setSelectedRoleIDs((current) =>
      selected ? [...current, roleID] : current.filter((value) => value !== roleID),
    )
  }

  async function savePolicy() {
    if (selectionRequired) {
      return
    }

    try {
      await updatePolicy.mutateAsync({
        access_mode: accessMode,
        allowed_role_ids: accessMode === 'allowed_roles' ? selectedRoleIDs : [],
      })

      toast.success('Application access updated', {
        description:
          accessMode === 'all_active_members'
            ? 'All active members can now use this application.'
            : 'Access is now limited to the selected roles.',
      })

      setOpen(false)
    } catch {
      // the request error is rendered inside the sheet.
    }
  }

  return (
    <Sheet open={open} onOpenChange={changeOpen}>
      <SheetTrigger asChild>
        <Button type="button" variant="outline" size="sm" className="rounded-lg">
          <Pencil aria-hidden="true" />
          Edit access
        </Button>
      </SheetTrigger>

      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader className="border-b border-border">
          <SheetTitle className="text-xl">Application access</SheetTitle>

          <SheetDescription>
            Choose which organization members can sign in to {application.name}.
          </SheetDescription>
        </SheetHeader>

        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(event) => {
            event.preventDefault()
            void savePolicy()
          }}
        >
          <div className="flex-1 space-y-7 overflow-y-auto px-6 py-6">
            <RequestError error={updatePolicy.error} />

            <FieldSet>
              <FieldLegend>Who can access this application?</FieldLegend>

              <FieldDescription>
                The policy is checked whenever Gatehouse processes an authorization request.
              </FieldDescription>

              <Select
                value={accessMode}
                onValueChange={(value) => changeAccessMode(value as ApplicationAccessMode)}
              >
                <SelectTrigger className="h-11 w-full rounded-lg">
                  <SelectValue />
                </SelectTrigger>

                <SelectContent>
                  <SelectItem value="all_active_members">All active members</SelectItem>
                  <SelectItem value="allowed_roles" disabled={roles.length === 0}>
                    Selected roles
                  </SelectItem>
                </SelectContent>
              </Select>

              {accessMode === 'allowed_roles' && (
                <div className="space-y-3">
                  {roles.map((role) => {
                    const checkboxID = `access-policy-role-${role.role_id}`

                    return (
                      <label
                        key={role.role_id}
                        htmlFor={checkboxID}
                        className="flex cursor-pointer items-start gap-3 rounded-xl border border-border bg-card p-4 transition-colors hover:border-primary/30"
                      >
                        <Checkbox
                          id={checkboxID}
                          checked={selectedRoleIDs.includes(role.role_id)}
                          onCheckedChange={(value) => toggleRole(role.role_id, value === true)}
                          className="mt-0.5"
                        />

                        <span className="min-w-0">
                          <span className="block text-sm font-semibold">{role.name}</span>

                          <span className="mt-1 block text-xs leading-5 text-muted-foreground">
                            {role.description || 'No description provided.'}
                          </span>
                        </span>
                      </label>
                    )
                  })}

                  {selectionRequired && <FieldError>Select at least one role.</FieldError>}
                </div>
              )}
            </FieldSet>
          </div>

          <SheetFooter className="border-t border-border">
            <SheetClose asChild>
              <Button
                type="button"
                variant="outline"
                disabled={updatePolicy.isPending}
                className="rounded-lg"
              >
                Cancel
              </Button>
            </SheetClose>

            <Button
              type="submit"
              disabled={updatePolicy.isPending || selectionRequired}
              className="rounded-lg"
            >
              {updatePolicy.isPending ? (
                <>
                  <Spinner />
                  Saving access
                </>
              ) : (
                <>
                  <Save aria-hidden="true" />
                  Save access
                </>
              )}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  )
}
