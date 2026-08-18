import { zodResolver } from '@hookform/resolvers/zod'
import { Plus, Send } from 'lucide-react'
import { Controller, useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'
import type { MembershipRole } from '@/api/members'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
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
import { useInviteMember } from '@/members/queries'
import { useState } from 'react'

const invitationSchema = z.object({
  email: z.string().trim().email('Enter a valid email address').max(254),
  role_id: z.string().min(1, 'Choose a role'),
})

type InvitationForm = z.infer<typeof invitationSchema>

export function InviteMemberSheet({ roles }: { roles: MembershipRole[] }) {
  const [open, setOpen] = useState(false)
  const invitation = useInviteMember()
  const defaultRoleID = findDefaultRoleID(roles)

  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<InvitationForm>({
    resolver: zodResolver(invitationSchema),
    defaultValues: {
      email: '',
      role_id: defaultRoleID,
    },
  })

  function changeOpen(nextOpen: boolean) {
    setOpen(nextOpen)

    if (!nextOpen) {
      invitation.reset()
      reset({
        email: '',
        role_id: defaultRoleID,
      })
    }
  }

  const submit = handleSubmit(async (form) => {
    try {
      const result = await invitation.mutateAsync(form)

      toast.success('Invitation sent', {
        description: `${result.email} was invited as ${result.role_name}.`,
      })

      changeOpen(false)
    } catch {
      // The mutation error is rendered inside the sheet.
    }
  })

  return (
    <Sheet open={open} onOpenChange={changeOpen}>
      <SheetTrigger asChild>
        <Button type="button" className="rounded-lg">
          <Plus aria-hidden="true" />
          Invite member
        </Button>
      </SheetTrigger>

      <SheetContent className="w-full sm:max-w-md">
        <SheetHeader className="border-b border-border">
          <SheetTitle className="text-xl">Invite a member</SheetTitle>
          <SheetDescription>Send someone an invitation to join this organization.</SheetDescription>
        </SheetHeader>

        <form onSubmit={submit} noValidate className="flex min-h-0 flex-1 flex-col">
          <div className="flex-1 space-y-6 overflow-y-auto px-6 py-6">
            <RequestError error={invitation.error} />

            <FieldGroup className="gap-5">
              <Field data-invalid={Boolean(errors.email) || undefined}>
                <FieldLabel htmlFor="invitation-email">Email address</FieldLabel>
                <Input
                  {...register('email')}
                  id="invitation-email"
                  type="email"
                  autoComplete="email"
                  autoFocus
                  aria-invalid={Boolean(errors.email)}
                  placeholder="colleague@company.com"
                  className="h-11 rounded-lg"
                />
                <FieldError errors={[errors.email]} />
              </Field>

              <Field data-invalid={Boolean(errors.role_id) || undefined}>
                <FieldLabel htmlFor="invitation-role">Role</FieldLabel>

                <Controller
                  name="role_id"
                  control={control}
                  render={({ field }) => (
                    <Select value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger
                        id="invitation-role"
                        className="h-11 w-full rounded-lg"
                        aria-invalid={Boolean(errors.role_id)}
                      >
                        <SelectValue placeholder="Choose a role" />
                      </SelectTrigger>

                      <SelectContent>
                        {roles.map((role) => (
                          <SelectItem key={role.role_id} value={role.role_id}>
                            {role.role_name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />

                <FieldError errors={[errors.role_id]} />
              </Field>
            </FieldGroup>
          </div>

          <SheetFooter className="border-t border-border">
            <SheetClose asChild>
              <Button
                type="button"
                variant="outline"
                disabled={invitation.isPending}
                className="rounded-lg"
              >
                Cancel
              </Button>
            </SheetClose>

            <Button type="submit" disabled={invitation.isPending} className="rounded-lg">
              {invitation.isPending ? (
                <>
                  <Spinner />
                  Sending invitation
                </>
              ) : (
                <>
                  <Send aria-hidden="true" />
                  Send invitation
                </>
              )}
            </Button>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  )
}

function findDefaultRoleID(roles: MembershipRole[]) {
  return roles.find((role) => role.role_key === 'member')?.role_id ?? roles[0]?.role_id ?? ''
}
