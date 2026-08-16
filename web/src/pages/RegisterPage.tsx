import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation } from '@tanstack/react-query'
import { ArrowRight, Check, ChevronLeft, MailCheck } from 'lucide-react'
import type { SubmitEvent } from 'react'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Link } from 'react-router-dom'
import { z } from 'zod'
import { register as registerAccount } from '@/api/auth'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'

const registrationSchema = z
  .object({
    tenant_name: z.string().trim().min(1, 'Organization name is required').max(200),
    tenant_slug: z
      .string()
      .trim()
      .min(1, 'Organization slug is required')
      .max(63)
      .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'Use lowercase letters, numbers, and single hyphens'),
    display_name: z.string().trim().min(1, 'Your name is required').max(200),
    email: z.string().trim().email('Enter a valid email address').max(254),
    password: z.string().min(12, 'Use at least 12 characters').max(1024),
    confirm_password: z.string(),
  })
  .refine((value) => value.password === value.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })

type RegistrationForm = z.infer<typeof registrationSchema>

type RegistrationStep = 'organization' | 'owner'

type RegistrationCompletion = {
  email: string
  tenantSlug: string
}

export function RegisterPage() {
  const [step, setStep] = useState<RegistrationStep>('organization')
  const [completion, setCompletion] = useState<RegistrationCompletion>()
  const [requestError, setRequestError] = useState<unknown>()

  const registrationMutation = useMutation({
    mutationFn: registerAccount,
  })

  const {
    register,
    handleSubmit,
    trigger,
    formState: { errors },
  } = useForm<RegistrationForm>({
    resolver: zodResolver(registrationSchema),
    shouldUnregister: false,
    defaultValues: {
      tenant_name: '',
      tenant_slug: '',
      display_name: '',
      email: '',
      password: '',
      confirm_password: '',
    },
  })

  const createOrganization = handleSubmit(async (form) => {
    setRequestError(undefined)

    try {
      await registrationMutation.mutateAsync({
        tenant_name: form.tenant_name,
        tenant_slug: form.tenant_slug,
        display_name: form.display_name,
        email: form.email,
        password: form.password,
      })

      setCompletion({
        email: form.email,
        tenantSlug: form.tenant_slug,
      })
    } catch (error) {
      setRequestError(error)
    }
  })
  async function continueToOwner() {
    setRequestError(undefined)

    const organizationIsValid = await trigger(['tenant_name', 'tenant_slug'], {
      shouldFocus: true,
    })

    if (organizationIsValid) {
      setStep('owner')
    }
  }

  function returnToOrganization() {
    setRequestError(undefined)
    setStep('organization')
  }

  async function submitForm(event: SubmitEvent<HTMLFormElement>) {
    if (step === 'organization') {
      event.preventDefault()
      await continueToOwner()
      return
    }

    await createOrganization(event)
  }

  if (completion) {
    return <RegistrationComplete email={completion.email} tenantSlug={completion.tenantSlug} />
  }

  return (
    <div>
      <header className="mb-7">
        <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em] text-foreground">
          Create your organization
        </h1>
      </header>

      <RegistrationProgress step={step} />

      <div className="mt-7 space-y-6">
        <RequestError error={requestError} />

        <form onSubmit={submitForm} noValidate className="space-y-7">
          {step === 'organization' ? (
            <section key="organization" className="space-y-5">
              <SectionHeading
                title="Organization details"
                description="Choose a name and organization slug."
              />

              <FieldGroup className="gap-5">
                <Field data-invalid={Boolean(errors.tenant_name) || undefined}>
                  <FieldLabel htmlFor="tenant-name">Organization name</FieldLabel>
                  <Input
                    {...register('tenant_name')}
                    id="tenant-name"
                    autoComplete="organization"
                    autoFocus
                    aria-invalid={Boolean(errors.tenant_name)}
                    placeholder="Acme Corporation"
                    className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
                  />
                  <FieldError errors={[errors.tenant_name]} />
                </Field>

                <Field data-invalid={Boolean(errors.tenant_slug) || undefined}>
                  <FieldLabel htmlFor="tenant-slug">Organization slug</FieldLabel>
                  <Input
                    {...register('tenant_slug')}
                    id="tenant-slug"
                    autoCapitalize="none"
                    autoComplete="off"
                    spellCheck={false}
                    aria-invalid={Boolean(errors.tenant_slug)}
                    placeholder="acme-corp"
                    className="h-11 rounded-lg border-border bg-card px-3 font-mono text-[0.82rem] shadow-xs"
                  />
                  <FieldDescription>
                    Used during sign-in and in tenant-specific URLs.
                  </FieldDescription>
                  <FieldError errors={[errors.tenant_slug]} />
                </Field>
              </FieldGroup>

              <Button type="submit" size="lg" className="h-11 w-full rounded-lg">
                Continue to Owner account
                <ArrowRight data-icon="inline-end" aria-hidden="true" />
              </Button>
            </section>
          ) : (
            <section key="owner" className="space-y-5">
              <SectionHeading
                title="Owner account"
                description="Create the first administrator for this organization."
              />

              <FieldGroup className="gap-5">
                <Field data-invalid={Boolean(errors.display_name) || undefined}>
                  <FieldLabel htmlFor="display-name">Your name</FieldLabel>
                  <Input
                    {...register('display_name')}
                    id="display-name"
                    autoComplete="name"
                    autoFocus
                    aria-invalid={Boolean(errors.display_name)}
                    placeholder="Avery Morgan"
                    className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
                  />
                  <FieldError errors={[errors.display_name]} />
                </Field>

                <Field data-invalid={Boolean(errors.email) || undefined}>
                  <FieldLabel htmlFor="registration-email">Work email</FieldLabel>
                  <Input
                    {...register('email')}
                    id="registration-email"
                    type="email"
                    autoComplete="email"
                    aria-invalid={Boolean(errors.email)}
                    placeholder="avery@company.com"
                    className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
                  />
                  <FieldError errors={[errors.email]} />
                </Field>

                <div className="grid gap-5 sm:grid-cols-2">
                  <Field data-invalid={Boolean(errors.password) || undefined}>
                    <FieldLabel htmlFor="new-password">Password</FieldLabel>
                    <Input
                      {...register('password')}
                      id="new-password"
                      type="password"
                      autoComplete="new-password"
                      aria-invalid={Boolean(errors.password)}
                      placeholder="12+ characters"
                      className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
                    />
                    <FieldError errors={[errors.password]} />
                  </Field>

                  <Field data-invalid={Boolean(errors.confirm_password) || undefined}>
                    <FieldLabel htmlFor="confirm-password">Confirm</FieldLabel>
                    <Input
                      {...register('confirm_password')}
                      id="confirm-password"
                      type="password"
                      autoComplete="new-password"
                      aria-invalid={Boolean(errors.confirm_password)}
                      placeholder="Repeat password"
                      className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
                    />
                    <FieldError errors={[errors.confirm_password]} />
                  </Field>
                </div>
              </FieldGroup>

              <div className="grid grid-cols-[auto_1fr] gap-3">
                <Button
                  type="button"
                  variant="outline"
                  size="lg"
                  disabled={registrationMutation.isPending}
                  onClick={returnToOrganization}
                  className="h-11 rounded-lg px-4"
                >
                  <ChevronLeft aria-hidden="true" />
                  Back
                </Button>

                <Button
                  type="submit"
                  size="lg"
                  disabled={registrationMutation.isPending}
                  className="h-11 rounded-lg"
                >
                  {registrationMutation.isPending ? (
                    <>
                      <Spinner />
                      Creating organization
                    </>
                  ) : (
                    <>
                      Create organization
                      <ArrowRight data-icon="inline-end" aria-hidden="true" />
                    </>
                  )}
                </Button>
              </div>
            </section>
          )}
        </form>

        <p className="text-center text-sm text-muted-foreground">
          Already have an organization?{' '}
          <Link
            to="/login"
            className="font-semibold text-foreground underline decoration-primary/30 underline-offset-4 transition-colors hover:text-primary"
          >
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}

function SectionHeading({ title, description }: { title: string; description: string }) {
  return (
    <header>
      <h2 className="text-sm font-semibold text-foreground">{title}</h2>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>
    </header>
  )
}

function RegistrationProgress({ step }: { step: RegistrationStep }) {
  const ownerStep = step === 'owner'

  return (
    <ol
      className="grid grid-cols-[auto_1fr_auto] items-center gap-3"
      aria-label="Registration progress"
    >
      <li
        className="flex items-center gap-2"
        aria-current={step === 'organization' ? 'step' : undefined}
      >
        <span
          className={[
            'grid size-6 place-items-center rounded-full text-[0.68rem] font-bold',
            ownerStep ? 'bg-primary/10 text-primary' : 'bg-primary text-primary-foreground',
          ].join(' ')}
        >
          {ownerStep ? <Check size={13} aria-hidden="true" /> : '1'}
        </span>

        <span
          className={[
            'text-xs font-semibold',
            !ownerStep ? 'text-foreground' : 'text-muted-foreground',
          ].join(' ')}
        >
          Organization
        </span>
      </li>

      <li
        className={['h-px', ownerStep ? 'bg-primary/40' : 'bg-border'].join(' ')}
        aria-hidden="true"
      />

      <li className="flex items-center gap-2" aria-current={ownerStep ? 'step' : undefined}>
        <span
          className={[
            'grid size-6 place-items-center rounded-full text-[0.68rem] font-bold',
            ownerStep
              ? 'bg-primary text-primary-foreground'
              : 'border border-border bg-card text-muted-foreground',
          ].join(' ')}
        >
          2
        </span>

        <span
          className={[
            'text-xs font-semibold',
            ownerStep ? 'text-foreground' : 'text-muted-foreground',
          ].join(' ')}
        >
          Owner
        </span>
      </li>
    </ol>
  )
}

function RegistrationComplete({ email, tenantSlug }: RegistrationCompletion) {
  const signInQuery = new URLSearchParams({
    tenant_slug: tenantSlug,
    email,
  })

  return (
    <div>
      <div className="mb-6 grid size-11 place-items-center rounded-lg border border-primary/15 bg-primary/8 text-primary">
        <MailCheck aria-hidden="true" />
      </div>

      <header className="mb-8">
        <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em] text-foreground">
          Check your email
        </h1>

        <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">
          We sent a verification link to{' '}
          <strong className="font-semibold text-foreground">{email}</strong>. Open it to activate
          your Owner account.
        </p>
      </header>

      <div className="mb-6 rounded-lg border border-border bg-card p-4">
        <p className="text-xs font-medium text-muted-foreground">Organization slug</p>
        <code className="mt-1 block text-sm font-semibold text-foreground">{tenantSlug}</code>
      </div>

      <p className="mb-6 text-xs leading-5 text-muted-foreground">
        The verification link expires in 24 hours.
      </p>

      <Button asChild variant="outline" size="lg" className="h-11 w-full rounded-lg">
        <Link to={`/login?${signInQuery.toString()}`}>Sign in after verifying</Link>
      </Button>
    </div>
  )
}
