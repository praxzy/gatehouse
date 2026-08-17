import { zodResolver } from '@hookform/resolvers/zod'
import { useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, QrCode, RefreshCw, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import { QRCodeSVG } from 'qrcode.react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { z } from 'zod'
import { beginTOTPEnrollment, confirmTOTPEnrollment } from '@/api/auth'
import type { TOTPEnrollment } from '@/api/auth'
import { APIError } from '@/api/client'
import { currentUserQueryKey, currentUserQueryOptions, useCurrentUser } from '@/auth/currentUser'
import { authenticatedDestination, safeReturnTo } from '@/auth/routing'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { InputOTP, InputOTPGroup, InputOTPSlot } from '@/components/ui/input-otp'
import { Spinner } from '@/components/ui/spinner'

const confirmationSchema = z.object({
  code: z
    .string()
    .trim()
    .regex(/^\d{6}$/, 'Enter the six-digit code'),
})

type ConfirmationForm = z.infer<typeof confirmationSchema>

export function MFAEnrollmentPage() {
  const currentUser = useCurrentUser()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  const [enrollment, setEnrollment] = useState<TOTPEnrollment | null>(null)
  const [enrollmentExpired, setEnrollmentExpired] = useState(false)
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [requestError, setRequestError] = useState<unknown>()
  const [starting, setStarting] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [continuing, setContinuing] = useState(false)
  const [saved, setSaved] = useState(false)
  const [manualKeyCopied, setManualKeyCopied] = useState(false)
  const [recoveryCodesCopied, setRecoveryCodesCopied] = useState(false)

  const returnTo = safeReturnTo(searchParams.get('return_to'))

  const {
    control,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ConfirmationForm>({
    resolver: zodResolver(confirmationSchema),
    defaultValues: {
      code: '',
    },
  })

  useEffect(() => {
    if (!enrollment) {
      return
    }

    const expiresAt = Date.parse(enrollment.expires_at)
    const remaining = Number.isNaN(expiresAt) ? 0 : Math.max(0, expiresAt - Date.now())

    const timeout = window.setTimeout(() => {
      setEnrollmentExpired(true)
    }, remaining)

    return () => {
      window.clearTimeout(timeout)
    }
  }, [enrollment])

  if (!currentUser.data) {
    return null
  }

  if (!recoveryCodes && currentUser.data.mfa_enrolled) {
    return <Navigate to={authenticatedDestination(currentUser.data, returnTo)} replace />
  }

  async function startEnrollment() {
    setRequestError(undefined)
    setStarting(true)
    setManualKeyCopied(false)

    try {
      const result = await beginTOTPEnrollment()
      setEnrollmentExpired(false)
      setEnrollment(result)
      reset()
    } catch (error) {
      setRequestError(error)
    } finally {
      setStarting(false)
    }
  }

  const confirmEnrollment = handleSubmit(async ({ code }) => {
    setRequestError(undefined)
    setConfirming(true)

    try {
      const result = await confirmTOTPEnrollment(code)

      setEnrollment(null)
      setRecoveryCodes(result.recovery_codes)
      reset()
    } catch (error) {
      if (error instanceof APIError && error.status === 410) {
        setEnrollmentExpired(true)
        setRequestError(undefined)
        reset()
        return
      }
      setRequestError(error)
    } finally {
      setConfirming(false)
    }
  })

  async function copyManualKey() {
    if (!enrollment) {
      return
    }

    try {
      await navigator.clipboard.writeText(enrollment.manual_key)
      setManualKeyCopied(true)
    } catch {
      setManualKeyCopied(false)
    }
  }

  async function copyRecoveryCodes() {
    if (!recoveryCodes) {
      return
    }

    try {
      await navigator.clipboard.writeText(recoveryCodes.join('\n'))
      setRecoveryCodesCopied(true)
    } catch {
      setRecoveryCodesCopied(false)
    }
  }

  async function continueToConsole() {
    setRequestError(undefined)
    setContinuing(true)

    try {
      queryClient.removeQueries({
        queryKey: currentUserQueryKey,
      })

      const user = await queryClient.fetchQuery(currentUserQueryOptions())

      setRecoveryCodes(null)

      navigate(authenticatedDestination(user, returnTo), { replace: true })
    } catch (error) {
      setRequestError(error)
    } finally {
      setContinuing(false)
    }
  }

  if (recoveryCodes) {
    return (
      <div>
        <PageHeader
          eyebrow="MFA enabled"
          title="Save your recovery codes"
          description="Use these codes if your authenticator is unavailable."
        />

        <div className="mt-7 space-y-6">
          <RequestError error={requestError} />

          <div className="border border-border bg-card">
            <div className="flex items-start justify-between gap-4 border-b border-border px-4 py-3">
              <div>
                <p className="text-sm font-semibold">One-time recovery codes</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Each code can only be used once.
                </p>
              </div>

              <ShieldCheck className="text-primary" size={19} aria-hidden="true" />
            </div>

            <div className="grid grid-cols-2 gap-px bg-border p-px sm:grid-cols-2">
              {recoveryCodes.map((code, index) => (
                <code
                  key={code}
                  className="bg-background px-3 py-3 text-center text-xs font-semibold tracking-[0.08em] text-foreground"
                >
                  <span className="mr-2 text-muted-foreground">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  {code}
                </code>
              ))}
            </div>
          </div>

          <Button
            type="button"
            variant="outline"
            size="lg"
            onClick={copyRecoveryCodes}
            className="h-11 w-full rounded-lg"
          >
            {recoveryCodesCopied ? (
              <>
                <Check aria-hidden="true" />
                Codes copied
              </>
            ) : (
              <>
                <Copy aria-hidden="true" />
                Copy all recovery codes
              </>
            )}
          </Button>

          <div className="flex items-start gap-3 border border-gatehouse-brass/40 bg-gatehouse-brass/8 p-4">
            <Checkbox
              id="recovery-codes-saved"
              checked={saved}
              onCheckedChange={(checked) => setSaved(checked === true)}
              className="mt-0.5"
            />

            <label htmlFor="recovery-codes-saved" className="cursor-pointer text-sm leading-5">
              I saved these codes. They will not be shown again.
            </label>
          </div>

          <Button
            type="button"
            size="lg"
            disabled={!saved || continuing}
            onClick={continueToConsole}
            className="h-11 w-full rounded-lg"
          >
            {continuing ? (
              <>
                <Spinner />
                Continuing
              </>
            ) : (
              <>
                Continue to Gatehouse
                <ShieldCheck data-icon="inline-end" aria-hidden="true" />
              </>
            )}
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        eyebrow="Multi-factor authentication"
        title="Set up an authenticator"
        description="Scan the QR code, then enter the generated code."
      />

      <div className="mt-7 space-y-6">
        <RequestError error={requestError} />

        {!enrollment ? (
          <>
            <div className="border border-border bg-card">
              <div className="grid grid-cols-[auto_1fr] gap-4 p-5">
                <div className="grid size-10 place-items-center bg-primary/10 text-primary">
                  <KeyRound size={19} aria-hidden="true" />
                </div>

                <div>
                  <h2 className="text-sm font-semibold">Authenticator application</h2>
                  <p className="mt-1 text-sm leading-6 text-muted-foreground">
                    Use 1Password, Aegis, Google Authenticator, or another TOTP-compatible
                    application.
                  </p>
                </div>
              </div>
            </div>

            <Button
              type="button"
              size="lg"
              onClick={startEnrollment}
              disabled={starting}
              className="h-11 w-full rounded-lg"
            >
              {starting ? (
                <>
                  <Spinner />
                  Preparing setup
                </>
              ) : (
                <>
                  <QrCode aria-hidden="true" />
                  Start authenticator setup
                </>
              )}
            </Button>
          </>
        ) : enrollmentExpired ? (
          <section className="border border-border bg-card p-5">
            <div className="grid grid-cols-[auto_1fr] gap-4">
              <div className="grid size-10 place-items-center bg-primary/10 text-primary">
                <RefreshCw size={19} aria-hidden="true" />
              </div>

              <div>
                <h2 className="text-sm font-semibold">Setup key expired</h2>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">
                  Generate a new QR code to continue setting up your authenticator.
                </p>
              </div>
            </div>

            <Button
              type="button"
              size="lg"
              onClick={startEnrollment}
              disabled={starting}
              className="mt-5 h-11 w-full rounded-lg"
            >
              {starting ? (
                <>
                  <Spinner />
                  Preparing setup
                </>
              ) : (
                <>
                  <RefreshCw aria-hidden="true" />
                  Generate new setup key
                </>
              )}
            </Button>
          </section>
        ) : (
          <>
            <section className="border border-border bg-card">
              <div className="border-b border-border px-4 py-3">
                <p className="text-xs font-semibold tracking-[0.12em] text-primary uppercase">
                  Step 1 · Scan
                </p>
                <h2 className="mt-1 text-sm font-semibold">Add Gatehouse to your authenticator</h2>
              </div>

              <div className="flex justify-center bg-white p-6">
                <div className="border border-border p-3">
                  <QRCodeSVG
                    value={enrollment.provisioning_uri}
                    size={188}
                    level="M"
                    title="Gatehouse authenticator QR code"
                  />
                </div>
              </div>

              <div className="border-t border-border p-4">
                <p className="text-xs font-medium">Unable to scan?</p>

                <div className="mt-2 flex items-center gap-2 border border-border bg-muted/40 p-2">
                  <code className="min-w-0 flex-1 text-xs font-semibold tracking-[0.08em] break-all">
                    {enrollment.manual_key}
                  </code>

                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    onClick={copyManualKey}
                    aria-label="Copy manual setup key"
                    title="Copy manual setup key"
                  >
                    {manualKeyCopied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  </Button>
                </div>
              </div>
            </section>

            <form onSubmit={confirmEnrollment} noValidate className="space-y-5">
              <div>
                <p className="text-xs font-semibold tracking-[0.12em] text-primary uppercase">
                  Step 2 · Confirm
                </p>
                <h2 className="mt-1 text-sm font-semibold">Verify the connection</h2>
              </div>

              <Field data-invalid={Boolean(errors.code) || undefined}>
                <FieldLabel htmlFor="enrollment-code">Six-digit code</FieldLabel>

                <Controller
                  name="code"
                  control={control}
                  render={({ field }) => (
                    <InputOTP
                      {...field}
                      id="enrollment-code"
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
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
                  Enter the current code shown in your authenticator.
                </FieldDescription>

                <FieldError errors={[errors.code]} />
              </Field>

              <Button
                type="submit"
                size="lg"
                disabled={confirming}
                className="h-11 w-full rounded-lg"
              >
                {confirming ? (
                  <>
                    <Spinner />
                    Verifying code
                  </>
                ) : (
                  <>
                    Verify and enable MFA
                    <ShieldCheck data-icon="inline-end" aria-hidden="true" />
                  </>
                )}
              </Button>
            </form>

            <Button
              type="button"
              variant="ghost"
              onClick={startEnrollment}
              disabled={starting || confirming}
              className="w-full rounded-lg"
            >
              <RefreshCw aria-hidden="true" />
              Generate a new setup key
            </Button>
          </>
        )}
      </div>
    </div>
  )
}

function PageHeader({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <header>
      <div className="mb-5 flex items-center gap-3 text-xs font-semibold tracking-[0.14em] text-primary uppercase">
        <span className="h-px w-7 bg-primary/50" />
        {eyebrow}
      </div>

      <h1 className="font-heading text-4xl leading-none font-medium tracking-[-0.035em]">
        {title}
      </h1>

      <p className="mt-4 max-w-sm text-sm leading-6 text-muted-foreground">{description}</p>
    </header>
  )
}
