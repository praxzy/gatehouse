import { useState } from 'react'
import { Clock3, Mail, UserCheck, UserRoundX, Users } from 'lucide-react'
import { toast } from 'sonner'
import type { Member, MembershipRole, OpenMembershipInvitation } from '@/api/members'
import { APIError } from '@/api/client'
import { ErrorReference } from '@/components/ErrorReference'
import { RequestError } from '@/components/RequestError'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Spinner } from '@/components/ui/spinner'
import { Surface } from '@/components/ui/surface'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { InviteMemberSheet } from '@/members/InviteMemberSheet'
import { useMembers, useUpdateMember } from '@/members/queries'

export function MembersPage() {
  const members = useMembers()

  if (members.isPending) {
    return (
      <PageContainer>
        <div
          className="flex min-h-80 items-center justify-center gap-3 text-sm font-medium text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Loading members
        </div>
      </PageContainer>
    )
  }

  if (members.isError) {
    return (
      <PageContainer>
        <Surface className="mx-auto max-w-xl p-6">
          <h1 className="font-heading text-2xl font-medium">Members couldn’t be loaded</h1>

          <div className="mt-4">
            <RequestError error={members.error} />
          </div>

          <Button
            type="button"
            variant="outline"
            onClick={() => members.refetch()}
            className="mt-5 rounded-lg"
          >
            Try again
          </Button>
        </Surface>
      </PageContainer>
    )
  }

  const activeMembers = members.data.members.filter((member) => member.status === 'active').length

  return (
    <PageContainer>
      <header className="motion-enter flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="font-mono text-[0.67rem] tracking-[0.14em] text-muted-foreground uppercase">
            Directory
          </p>

          <h1 className="mt-2 font-heading text-4xl font-medium tracking-[-0.035em]">Members</h1>

          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            {activeMembers} active {activeMembers === 1 ? 'member' : 'members'} in this
            organization.
          </p>
        </div>

        <InviteMemberSheet roles={members.data.roles} />
      </header>

      <Tabs defaultValue="members" className="motion-enter motion-enter-delay-1 mt-8">
        <TabsList variant="line" className="gap-5">
          <TabsTrigger value="members" className="px-0">
            Members
            <CountBadge value={members.data.members.length} />
          </TabsTrigger>

          <TabsTrigger value="invitations" className="px-0">
            Invitations
            <CountBadge value={members.data.invitations.length} />
          </TabsTrigger>
        </TabsList>

        <TabsContent value="members" className="mt-5">
          <MemberDirectory members={members.data.members} roles={members.data.roles} />
        </TabsContent>

        <TabsContent value="invitations" className="mt-5">
          <InvitationDirectory invitations={members.data.invitations} />
        </TabsContent>
      </Tabs>
    </PageContainer>
  )
}

function MemberDirectory({ members, roles }: { members: Member[]; roles: MembershipRole[] }) {
  if (members.length === 0) {
    return (
      <EmptyDirectory
        icon={Users}
        title="No members yet"
        description="Invite someone to begin building your organization directory."
      />
    )
  }

  return (
    <Surface className="divide-y divide-border">
      {members.map((member) => (
        <MemberRow key={member.membership_id} member={member} roles={roles} />
      ))}
    </Surface>
  )
}

function MemberRow({ member, roles }: { member: Member; roles: MembershipRole[] }) {
  const updateMember = useUpdateMember()
  const [proposedRoleID, setProposedRoleID] = useState<string>()

  const proposedRole = roles.find((role) => role.role_id === proposedRoleID)
  const pendingRoleID = updateMember.variables?.input.role_id
  const displayedRoleID =
    proposedRoleID ?? (updateMember.isPending && pendingRoleID ? pendingRoleID : member.role_id)

  function proposeRoleChange(roleID: string) {
    if (roleID === member.role_id) {
      return
    }

    setProposedRoleID(roleID)
  }

  async function confirmRoleChange() {
    if (!proposedRole) {
      return
    }

    const targetRole = proposedRole

    try {
      await updateMember.mutateAsync({
        membershipId: member.membership_id,
        input: {
          role_id: targetRole.role_id,
        },
      })

      toast.success('Role updated', {
        description: `${member.display_name} is now ${targetRole.role_name}.`,
      })
    } catch (error) {
      showMemberUpdateError('Could not update role', error)
    } finally {
      setProposedRoleID(undefined)
    }
  }

  async function changeStatus(status: 'active' | 'disabled') {
    try {
      await updateMember.mutateAsync({
        membershipId: member.membership_id,
        input: { status },
      })

      toast.success(status === 'disabled' ? 'Member disabled' : 'Member reactivated', {
        description:
          status === 'disabled'
            ? `${member.display_name} can no longer access this organization.`
            : `${member.display_name} can access this organization again.`,
      })
    } catch (error) {
      showMemberUpdateError(
        status === 'disabled' ? 'Could not disable member' : 'Could not reactivate member',
        error,
      )
    }
  }

  return (
    <div className="grid gap-5 px-5 py-5 sm:px-6 lg:grid-cols-[minmax(14rem,1fr)_10rem_12rem_auto] lg:items-center">
      <div className="flex min-w-0 items-center gap-3">
        <div
          className="grid size-10 shrink-0 place-items-center rounded-lg bg-primary/8 text-xs font-semibold text-primary"
          aria-hidden="true"
        >
          {initials(member.display_name)}
        </div>

        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="truncate text-sm font-semibold">{member.display_name}</p>

            <StatusBadge status={member.status} />
          </div>

          <p className="mt-1 truncate text-xs text-muted-foreground">{member.email}</p>
        </div>
      </div>

      <div>
        <p className="mb-1.5 text-[0.62rem] font-semibold tracking-[0.12em] text-muted-foreground uppercase lg:hidden">
          Joined
        </p>
        <p className="text-sm text-muted-foreground">{formatDate(member.created_at)}</p>
      </div>

      <div>
        <label
          htmlFor={`member-role-${member.membership_id}`}
          className="mb-1.5 block text-[0.62rem] font-semibold tracking-[0.12em] text-muted-foreground uppercase lg:sr-only"
        >
          Role
        </label>

        <Select
          value={displayedRoleID}
          onValueChange={proposeRoleChange}
          disabled={updateMember.isPending}
        >
          <SelectTrigger
            id={`member-role-${member.membership_id}`}
            className="h-9 w-full rounded-lg"
            aria-label={`Role for ${member.display_name}`}
          >
            <SelectValue />
          </SelectTrigger>

          <SelectContent>
            {roles.map((role) => (
              <SelectItem key={role.role_id} value={role.role_id}>
                {role.role_name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <AlertDialog
          open={proposedRole !== undefined}
          onOpenChange={(open) => {
            if (!open) {
              setProposedRoleID(undefined)
            }
          }}
        >
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Change {member.display_name}’s role?</AlertDialogTitle>

              <AlertDialogDescription>
                Change their role from {member.role_name} to {proposedRole?.role_name}. Their
                permissions will update immediately.
              </AlertDialogDescription>
            </AlertDialogHeader>

            <AlertDialogFooter>
              <AlertDialogCancel>Keep current role</AlertDialogCancel>

              <AlertDialogAction onClick={() => void confirmRoleChange()}>
                Change role
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>

      <div className="flex justify-end">
        {member.status === 'disabled' ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={updateMember.isPending}
            onClick={() => changeStatus('active')}
            className="w-full rounded-lg lg:w-auto"
          >
            {updateMember.isPending ? <Spinner /> : <UserCheck aria-hidden="true" />}
            Reactivate
          </Button>
        ) : (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={updateMember.isPending}
                className="w-full rounded-lg text-muted-foreground lg:w-auto"
              >
                <UserRoundX aria-hidden="true" />
                Disable
              </Button>
            </AlertDialogTrigger>

            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Disable {member.display_name}?</AlertDialogTitle>

                <AlertDialogDescription>
                  They will lose access to this organization and their active Gatehouse sessions
                  will be revoked.
                </AlertDialogDescription>
              </AlertDialogHeader>

              <AlertDialogFooter>
                <AlertDialogCancel>Keep active</AlertDialogCancel>

                <AlertDialogAction onClick={() => changeStatus('disabled')}>
                  Disable member
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}
      </div>
    </div>
  )
}

function InvitationDirectory({ invitations }: { invitations: OpenMembershipInvitation[] }) {
  if (invitations.length === 0) {
    return (
      <EmptyDirectory
        icon={Mail}
        title="No pending invitations"
        description="Outstanding invitations will appear here."
      />
    )
  }

  return (
    <Surface className="divide-y divide-border">
      {invitations.map((invitation) => (
        <div
          key={invitation.invitation_id}
          className="grid gap-4 px-5 py-5 sm:grid-cols-[minmax(0,1fr)_10rem_auto] sm:items-center sm:px-6"
        >
          <div className="flex min-w-0 items-center gap-3">
            <div
              className="grid size-10 shrink-0 place-items-center rounded-lg bg-gatehouse-brass/10 text-gatehouse-brass"
              aria-hidden="true"
            >
              <Mail size={17} />
            </div>

            <div className="min-w-0">
              <p className="truncate text-sm font-semibold">{invitation.email}</p>
              <p className="mt-1 text-xs text-muted-foreground">
                Invited as {invitation.role_name}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Clock3 size={14} aria-hidden="true" />
            {invitation.expired ? 'Expired' : `Expires ${formatDate(invitation.expires_at)}`}
          </div>

          <span
            className={
              invitation.expired
                ? 'w-fit rounded-full bg-destructive/8 px-2.5 py-1 text-[0.68rem] font-semibold text-destructive'
                : 'w-fit rounded-full bg-gatehouse-brass/10 px-2.5 py-1 text-[0.68rem] font-semibold text-gatehouse-brass'
            }
          >
            {invitation.expired ? 'Expired' : 'Pending'}
          </span>
        </div>
      ))}
    </Surface>
  )
}

function EmptyDirectory({
  icon: Icon,
  title,
  description,
}: {
  icon: typeof Users
  title: string
  description: string
}) {
  return (
    <Surface className="grid min-h-64 place-items-center p-8 text-center">
      <div>
        <div className="mx-auto grid size-11 place-items-center rounded-lg bg-muted text-muted-foreground">
          <Icon size={19} aria-hidden="true" />
        </div>

        <h2 className="mt-4 font-heading text-xl font-medium">{title}</h2>

        <p className="mt-2 text-sm text-muted-foreground">{description}</p>
      </div>
    </Surface>
  )
}

function StatusBadge({ status }: { status: Member['status'] }) {
  return (
    <span
      className={
        status === 'active'
          ? 'rounded-full bg-primary/8 px-2 py-0.5 text-[0.62rem] font-semibold text-primary'
          : 'rounded-full bg-muted px-2 py-0.5 text-[0.62rem] font-semibold text-muted-foreground'
      }
    >
      {status === 'active' ? 'Active' : 'Disabled'}
    </span>
  )
}

function CountBadge({ value }: { value: number }) {
  return <span className="rounded-full bg-muted px-1.5 py-0.5 text-[0.65rem]">{value}</span>
}

function PageContainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto w-full max-w-376 px-5 py-7 sm:px-7 lg:px-10 lg:py-9">{children}</div>
  )
}

function initials(name: string) {
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('')
}

function formatDate(value: string) {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return 'Unknown'
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
  }).format(date)
}

function showMemberUpdateError(title: string, error: unknown) {
  toast.error(title, {
    description:
      error instanceof APIError ? (
        <div>
          <p>{error.message}</p>
          <ErrorReference requestId={error.requestId} />
        </div>
      ) : (
        'Please try again.'
      ),
  })
}
