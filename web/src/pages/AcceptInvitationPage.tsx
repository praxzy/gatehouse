import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ArrowRight, CheckCircle2, Mail, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { Link } from 'react-router-dom'
import { z } from 'zod'
import {
  acceptMembershipInvitation,
  previewMembershipInvitation,
  type MembershipInvitationPreview,
} from '@/api/members'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'

const accountSetupSchema = z
  .object({
    display_name: z.string().trim().min(1, 'Your name is required').max(200),
    password: z.string().min(12, 'Use at least 12 characters').max(1024),
    confirm_password: z.string(),
  })
  .refine((value) => value.password === value.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })

type AccountSetupForm = z.infer<typeof accountSetupSchema>

export function AcceptInvitationPage() {
  const [token] = useState(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1))
    return fragment.get('token')?.trim() ?? ''
  })

  useEffect(() => {
    if (!window.location.hash) {
      return
    }

    window.history.replaceState(
      window.history.state,
      '',
      window.location.pathname + window.location.search,
    )
  }, [])

  const invitation = useQuery({
    queryKey: ['membership-invitation', token],
    queryFn: () => previewMembershipInvitation(token),
    enabled: token !== '',
    retry: false,
  })

  if (!token) {
    return (
      <InvitationFrame
        title="Invitation link unavailable"
        description="This invitation link is incomplete. Open the complete link from your email."
      >
        <Button asChild size="lg" className="h-11 w-full rounded-lg">
          <Link to="/login">Return to sign in</Link>
        </Button>
      </InvitationFrame>
    )
  }

  if (invitation.isPending) {
    return (
      <InvitationFrame
        icon={<Mail aria-hidden="true" />}
        title="Opening your invitation"
        description="This should only take a moment."
      >
        <div
          className="flex items-center justify-center gap-3 py-3 text-sm font-medium text-muted-foreground"
          aria-live="polite"
        >
          <Spinner />
          Checking invitation
        </div>
      </InvitationFrame>
    )
  }

  if (invitation.isError) {
    return (
      <InvitationFrame
        title="This invitation isn’t available"
        description="It may have expired, already been accepted, or been replaced by a newer invitation."
      >
        <div className="space-y-4">
          <RequestError error={invitation.error} />

          <Button asChild variant="outline" size="lg" className="h-11 w-full rounded-lg">
            <Link to="/login">Return to sign in</Link>
          </Button>
        </div>
      </InvitationFrame>
    )
  }

  return <InvitationAcceptance token={token} invitation={invitation.data} />
}

function InvitationAcceptance({
  token,
  invitation,
}: {
  token: string
  invitation: MembershipInvitationPreview
}) {
  const acceptance = useMutation({
    mutationFn: acceptMembershipInvitation,
  })

  if (acceptance.isSuccess) {
    return (
      <InvitationFrame
        icon={<CheckCircle2 aria-hidden="true" />}
        title={`You’ve joined ${invitation.tenant_name}`}
        description="Your membership is ready. Sign in using the organization slug below."
      >
        <InvitationSummary invitation={invitation} />

        <Button asChild size="lg" className="mt-6 h-11 w-full rounded-lg">
          <Link to={`/login?tenant=${encodeURIComponent(invitation.tenant_slug)}`}>
            Continue to sign in
            <ArrowRight aria-hidden="true" />
          </Link>
        </Button>
      </InvitationFrame>
    )
  }

  return (
    <InvitationFrame
      icon={<Users aria-hidden="true" />}
      title={`Join ${invitation.tenant_name}`}
      description={`You’ve been invited as ${invitation.role_name}.`}
    >
      <InvitationSummary invitation={invitation} />

      <div className="mt-7">
        {invitation.account_setup_required ? (
          <AccountSetupForm
            token={token}
            isPending={acceptance.isPending}
            error={acceptance.error}
            onAccept={(input) => acceptance.mutateAsync(input)}
          />
        ) : (
          <ExistingAccountAcceptance
            token={token}
            isPending={acceptance.isPending}
            error={acceptance.error}
            onAccept={(input) => acceptance.mutateAsync(input)}
          />
        )}
      </div>
    </InvitationFrame>
  )
}

function AccountSetupForm({
  token,
  isPending,
  error,
  onAccept,
}: {
  token: string
  isPending: boolean
  error: unknown
  onAccept: (input: { token: string; display_name: string; password: string }) => Promise<unknown>
}) {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<AccountSetupForm>({
    resolver: zodResolver(accountSetupSchema),
    defaultValues: {
      display_name: '',
      password: '',
      confirm_password: '',
    },
  })

  const submit = handleSubmit(async (form) => {
    try {
      await onAccept({
        token,
        display_name: form.display_name,
        password: form.password,
      })
    } catch {
      // The mutation exposes the error through its error state.
    }
  })

  return (
    <form onSubmit={submit} noValidate className="space-y-6">
      <RequestError error={error} />

      <FieldGroup className="gap-5">
        <Field data-invalid={Boolean(errors.display_name) || undefined}>
          <FieldLabel htmlFor="invitation-display-name">Your name</FieldLabel>
          <Input
            {...register('display_name')}
            id="invitation-display-name"
            autoComplete="name"
            autoFocus
            aria-invalid={Boolean(errors.display_name)}
            placeholder="Avery Morgan"
            className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
          />
          <FieldError errors={[errors.display_name]} />
        </Field>

        <Field data-invalid={Boolean(errors.password) || undefined}>
          <FieldLabel htmlFor="invitation-password">Create password</FieldLabel>
          <Input
            {...register('password')}
            id="invitation-password"
            type="password"
            autoComplete="new-password"
            aria-invalid={Boolean(errors.password)}
            className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
          />
          <FieldError errors={[errors.password]} />
        </Field>

        <Field data-invalid={Boolean(errors.confirm_password) || undefined}>
          <FieldLabel htmlFor="invitation-confirm-password">Confirm password</FieldLabel>
          <Input
            {...register('confirm_password')}
            id="invitation-confirm-password"
            type="password"
            autoComplete="new-password"
            aria-invalid={Boolean(errors.confirm_password)}
            className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
          />
          <FieldError errors={[errors.confirm_password]} />
        </Field>
      </FieldGroup>

      <Button type="submit" size="lg" disabled={isPending} className="h-11 w-full rounded-lg">
        {isPending ? (
          <>
            <Spinner />
            Joining organization
          </>
        ) : (
          <>
            Accept invitation
            <ArrowRight aria-hidden="true" />
          </>
        )}
      </Button>
    </form>
  )
}

function ExistingAccountAcceptance({
  token,
  isPending,
  error,
  onAccept,
}: {
  token: string
  isPending: boolean
  error: unknown
  onAccept: (input: { token: string }) => Promise<unknown>
}) {
  async function acceptInvitation() {
    try {
      await onAccept({ token })
    } catch {
      // The mutation exposes the error through its error state.
    }
  }

  return (
    <div className="space-y-5">
      <RequestError error={error} />

      <p className="text-sm leading-6 text-muted-foreground">
        This invitation matches an existing Gatehouse account. You won’t need to create another
        password.
      </p>

      <Button
        type="button"
        size="lg"
        disabled={isPending}
        onClick={acceptInvitation}
        className="h-11 w-full rounded-lg"
      >
        {isPending ? (
          <>
            <Spinner />
            Joining organization
          </>
        ) : (
          <>
            Accept invitation
            <ArrowRight aria-hidden="true" />
          </>
        )}
      </Button>
    </div>
  )
}

function InvitationSummary({ invitation }: { invitation: MembershipInvitationPreview }) {
  return (
    <dl className="divide-y divide-border rounded-xl border border-border bg-card px-4 shadow-xs">
      <div className="flex items-center justify-between gap-4 py-3">
        <dt className="text-sm text-muted-foreground">Email</dt>
        <dd className="truncate text-sm font-medium">{invitation.email}</dd>
      </div>

      <div className="flex items-center justify-between gap-4 py-3">
        <dt className="text-sm text-muted-foreground">Organization</dt>
        <dd className="truncate text-sm font-medium">{invitation.tenant_name}</dd>
      </div>

      <div className="flex items-center justify-between gap-4 py-3">
        <dt className="text-sm text-muted-foreground">Role</dt>
        <dd className="text-sm font-medium">{invitation.role_name}</dd>
      </div>
    </dl>
  )
}

function InvitationFrame({
  icon,
  title,
  description,
  children,
}: {
  icon?: React.ReactNode
  title: string
  description: string
  children: React.ReactNode
}) {
  return (
    <div>
      {icon && (
        <div className="mb-6 grid size-11 place-items-center rounded-lg border border-primary/15 bg-primary/8 text-primary">
          {icon}
        </div>
      )}

      <header className="mb-8">
        <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em] text-foreground">
          {title}
        </h1>

        <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">{description}</p>
      </header>

      {children}
    </div>
  )
}
