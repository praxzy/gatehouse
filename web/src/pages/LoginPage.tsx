import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRight } from 'lucide-react'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { login } from '@/api/auth'
import { currentUserQueryKey, currentUserQueryOptions } from '@/auth/currentUser'
import { authenticatedDestination } from '@/auth/routing'
import { RequestError } from '@/components/RequestError'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Field, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'

const loginSchema = z.object({
  tenant_slug: z.string().trim().min(1, 'Organization slug is required'),
  email: z.string().trim().email('Enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
})

type LoginForm = z.infer<typeof loginSchema>

export function LoginPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()
  const [requestError, setRequestError] = useState<unknown>()

  const loginMutation = useMutation({
    mutationFn: login,
  })

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      tenant_slug: searchParams.get('tenant_slug') ?? '',
      email: searchParams.get('email') ?? '',
      password: '',
    },
  })

  const submit = handleSubmit(async (input) => {
    setRequestError(undefined)

    try {
      await loginMutation.mutateAsync(input)

      queryClient.removeQueries({
        queryKey: currentUserQueryKey,
      })

      const user = await queryClient.fetchQuery(currentUserQueryOptions())

      toast.success('Password accepted')

      navigate(authenticatedDestination(user, searchParams.get('return_to')), {
        replace: true,
      })
    } catch (error) {
      setRequestError(error)
    }
  })

  return (
    <div>
      <header className="mb-8">
        <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em] text-foreground">
          Welcome back
        </h1>

        <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">
          Sign in to your organization.
        </p>
      </header>

      <div className="space-y-5">
        <RequestError error={requestError} />

        <form onSubmit={submit} noValidate className="space-y-6">
          <FieldGroup className="gap-5">
            <Field data-invalid={Boolean(errors.tenant_slug) || undefined}>
              <FieldLabel htmlFor="tenant-slug">Organization slug</FieldLabel>
              <Input
                {...register('tenant_slug')}
                id="tenant-slug"
                autoCapitalize="none"
                autoComplete="organization"
                spellCheck={false}
                aria-invalid={Boolean(errors.tenant_slug)}
                placeholder="acme-corp"
                className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
              />
              <FieldError errors={[errors.tenant_slug]} />
            </Field>

            <Field data-invalid={Boolean(errors.email) || undefined}>
              <FieldLabel htmlFor="email">Email address</FieldLabel>
              <Input
                {...register('email')}
                id="email"
                type="email"
                autoComplete="email"
                aria-invalid={Boolean(errors.email)}
                placeholder="you@company.com"
                className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
              />
              <FieldError errors={[errors.email]} />
            </Field>

            <Field data-invalid={Boolean(errors.password) || undefined}>
              <FieldLabel htmlFor="password">Password</FieldLabel>
              <Input
                {...register('password')}
                id="password"
                type="password"
                autoComplete="current-password"
                aria-invalid={Boolean(errors.password)}
                placeholder="Enter your password"
                className="h-11 rounded-lg border-border bg-card px-3 shadow-xs"
              />
              <FieldError errors={[errors.password]} />
            </Field>
          </FieldGroup>

          <Button
            type="submit"
            size="lg"
            disabled={loginMutation.isPending}
            className="h-11 w-full rounded-lg"
          >
            {loginMutation.isPending ? (
              <>
                <Spinner />
                Signing in
              </>
            ) : (
              <>
                Sign in
                <ArrowRight data-icon="inline-end" aria-hidden="true" />
              </>
            )}
          </Button>
        </form>

        <div className="flex items-center gap-4 py-1">
          <span className="h-px flex-1 bg-border" />
          <span className="text-[0.68rem] font-medium tracking-[0.12em] text-muted-foreground uppercase">
            New organization
          </span>
          <span className="h-px flex-1 bg-border" />
        </div>

        <p className="text-center text-sm text-muted-foreground">
          Need a Gatehouse tenant?{' '}
          <Link
            to="/register"
            className="font-semibold text-foreground underline decoration-primary/30 underline-offset-4 transition-colors hover:text-primary"
          >
            Create an organization
          </Link>
        </p>
      </div>
    </div>
  )
}
