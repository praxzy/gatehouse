import { zodResolver } from '@hookform/resolvers/zod'
import { useQueryClient } from '@tanstack/react-query'
import { Fingerprint, KeyRound, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { completeRecoveryChallenge, completeTOTPChallenge } from '@/api/auth'
import { currentUserQueryKey, currentUserQueryOptions, useCurrentUser } from '@/auth/currentUser'
import { authenticatedDestination, isAuthorizationContinuation, safeReturnTo } from '@/auth/routing'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import { Spinner } from '@/components/ui/spinner'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

const challengeSchema = z.object({
  code: z.string().trim().min(1, 'Enter an authentication code'),
})

type ChallengeForm = z.infer<typeof challengeSchema>
type ChallengeMode = 'totp' | 'recovery'

export function MFAChallengePage() {
  const currentUser = useCurrentUser()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [mode, setMode] = useState<ChallengeMode>('totp')
  const [requestError, setRequestError] = useState<unknown>()
  const [submitting, setSubmitting] = useState(false)

  const returnTo = safeReturnTo(searchParams.get('return_to'))

  const {
    control,
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<ChallengeForm>({
    resolver: zodResolver(challengeSchema),
    defaultValues: {
      code: '',
    },
  })

  if (!currentUser.data) {
    return null
  }

  if (currentUser.data.fully_authenticated) {
    return <Navigate to={returnTo} replace />
  }

  if (!currentUser.data.mfa_enrolled) {
    const query = returnTo === '/app' ? '' : `?return_to=${encodeURIComponent(returnTo)}`

    return <Navigate to={`/mfa/enroll${query}`} replace />
  }

  function changeMode(value: string) {
    const nextMode: ChallengeMode = value === 'recovery' ? 'recovery' : 'totp'

    setMode(nextMode)
    setRequestError(undefined)
    reset()
  }

  const submit = handleSubmit(async ({ code }) => {
    if (mode === 'totp' && !/^\d{6}$/.test(code)) {
      setError('code', {
        message: 'Enter the six-digit code',
      })
      return
    }

    setRequestError(undefined)
    setSubmitting(true)

    try {
      if (mode === 'totp') {
        await completeTOTPChallenge(code)
      } else {
        await completeRecoveryChallenge(code)
      }

      queryClient.removeQueries({
        queryKey: currentUserQueryKey,
      })

      const user = await queryClient.fetchQuery(currentUserQueryOptions())

      const destination = authenticatedDestination(user, returnTo)

      if (isAuthorizationContinuation(destination)) {
        window.location.assign(destination)
        return
      }

      navigate(destination, { replace: true })
    } catch (error) {
      setRequestError(error)
    } finally {
      setSubmitting(false)
    }
  })

  return (
    <div>
      <header>
        <div className="mb-5 flex items-center gap-3 text-xs font-semibold tracking-[0.14em] text-primary uppercase">
          <span className="h-px w-7 bg-primary/50" />
          Multi-factor authentication
        </div>

        <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em]">
          Enter a verification code
        </h1>

        <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">
          Use your authenticator or a recovery code.
        </p>
      </header>

      <div className="mt-7 space-y-6">
        <div className="grid grid-cols-[auto_1fr_auto] items-center gap-3 border border-border bg-card px-4 py-3">
          <div className="grid size-9 place-items-center bg-primary/10 text-primary">
            <ShieldCheck size={18} aria-hidden="true" />
          </div>

          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">{currentUser.data.tenant_name}</p>
            <p className="truncate text-xs text-muted-foreground">{currentUser.data.email}</p>
          </div>

          <span className="text-[0.68rem] font-semibold tracking-[0.1em] text-gatehouse-brass uppercase">
            MFA required
          </span>
        </div>

        <Tabs value={mode} onValueChange={changeMode} className="gap-5">
          <TabsList className="grid h-10 w-full grid-cols-2 rounded-lg">
            <TabsTrigger value="totp" disabled={submitting} className="rounded-md">
              <Fingerprint aria-hidden="true" />
              Authenticator
            </TabsTrigger>

            <TabsTrigger value="recovery" disabled={submitting} className="rounded-md">
              <KeyRound aria-hidden="true" />
              Recovery code
            </TabsTrigger>
          </TabsList>

          <RequestError error={requestError} />

          <form onSubmit={submit} noValidate className="space-y-5">
            {mode === 'totp' ? (
              <Field key="totp" data-invalid={Boolean(errors.code) || undefined}>
                <FieldLabel htmlFor="challenge-code">Six-digit code</FieldLabel>

                <Controller
                  name="code"
                  control={control}
                  render={({ field }) => (
                    <InputOTP
                      {...field}
                      id="challenge-code"
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      autoFocus
                      aria-invalid={Boolean(errors.code)}
                      containerClassName="justify-center"
                    >
                      <InputOTPGroup className="rounded-lg">
                        {Array.from({ length: 6 }, (_, index) => (
                          <InputOTPSlot
                            key={index}
                            index={index}
                            className="size-11 first:rounded-l-lg last:rounded-r-lg"
                          />
                        ))}
                      </InputOTPGroup>
                    </InputOTP>
                  )}
                />

                <FieldDescription>
                  Enter the current code from your authenticator application.
                </FieldDescription>

                <FieldError errors={[errors.code]} />
              </Field>
            ) : (
              <Field key="recovery" data-invalid={Boolean(errors.code) || undefined}>
                <FieldLabel htmlFor="recovery-code">Recovery code</FieldLabel>

                <Input
                  {...register('code')}
                  id="recovery-code"
                  autoFocus
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  maxLength={64}
                  aria-invalid={Boolean(errors.code)}
                  placeholder="Enter an unused recovery code"
                  className="h-11 rounded-lg border-border bg-card px-3 font-mono text-sm tracking-[0.08em] uppercase shadow-xs"
                />

                <FieldDescription>
                  Recovery codes are single-use. Gatehouse will reject a code that has already been
                  consumed.
                </FieldDescription>

                <FieldError errors={[errors.code]} />
              </Field>
            )}

            <Button
              type="submit"
              size="lg"
              disabled={submitting}
              className="h-11 w-full rounded-lg"
            >
              {submitting ? (
                <>
                  <Spinner />
                  Verifying identity
                </>
              ) : (
                <>
                  Verify and continue
                  <ShieldCheck data-icon="inline-end" aria-hidden="true" />
                </>
              )}
            </Button>
          </form>
        </Tabs>
      </div>
    </div>
  )
}
