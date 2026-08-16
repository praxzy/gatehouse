import { useMutation } from '@tanstack/react-query'
import { CheckCircle2, MailCheck, RotateCcw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { verifyEmail } from '@/api/auth'
import { RequestError } from '@/components/RequestError'
import { Button } from '@/components/ui/button'
import { Spinner } from '@/components/ui/spinner'

export function VerifyEmailPage() {
  const [token] = useState(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1))
    return fragment.get('token')?.trim() ?? ''
  })

  const [verificationAlreadyCompleted] = useState(() => {
    const search = new URLSearchParams(window.location.search)
    return search.get('verified') === '1'
  })

  const {
    mutate: submitVerification,
    isPending,
    isSuccess,
    isError,
    error,
  } = useMutation({
    mutationFn: verifyEmail,
  })

  useEffect(() => {
    if (window.location.hash) {
      window.history.replaceState(
        window.history.state,
        '',
        window.location.pathname + window.location.search,
      )
    }

    if (!token) {
      return
    }

    const verificationTimer = window.setTimeout(() => {
      submitVerification(token)
    }, 0)

    return () => {
      window.clearTimeout(verificationTimer)
    }
  }, [token, submitVerification])

  useEffect(() => {
    if (!isSuccess) {
      return
    }

    const search = new URLSearchParams(window.location.search)
    search.set('verified', '1')

    window.history.replaceState(
      window.history.state,
      '',
      `${window.location.pathname}?${search.toString()}`,
    )
  }, [isSuccess])

  if (!token) {
    return (
      <VerificationMessage
        title="Verification link unavailable"
        description="This verification link is incomplete. Open the complete link from your email."
      >
        <Button asChild size="lg" className="h-11 w-full rounded-lg">
          <Link to="/login">Return to sign in</Link>
        </Button>
      </VerificationMessage>
    )
  }

  if (verificationAlreadyCompleted || isSuccess) {
    return (
      <VerificationMessage
        icon={<CheckCircle2 aria-hidden="true" />}
        title="Email verified"
        description="Your email address has been confirmed. You can now sign in to your organization."
      >
        <Button asChild size="lg" className="h-11 w-full rounded-lg">
          <Link to="/login">Continue to sign in</Link>
        </Button>
      </VerificationMessage>
    )
  }

  if (isError) {
    return (
      <VerificationMessage
        title="We couldn’t verify your email"
        description="The link may be invalid, expired, or already used."
      >
        <div className="space-y-4">
          <RequestError error={error} />

          <Button
            type="button"
            variant="outline"
            size="lg"
            disabled={isPending}
            onClick={() => submitVerification(token)}
            className="h-11 w-full rounded-lg"
          >
            <RotateCcw aria-hidden="true" />
            Try again
          </Button>

          <Button asChild variant="ghost" size="lg" className="h-11 w-full rounded-lg">
            <Link to="/login">Return to sign in</Link>
          </Button>
        </div>
      </VerificationMessage>
    )
  }

  return (
    <VerificationMessage
      icon={<MailCheck aria-hidden="true" />}
      title="Verifying your email"
      description="This should only take a moment."
    >
      <div
        className="flex items-center justify-center gap-3 py-3 text-sm font-medium text-muted-foreground"
        aria-live="polite"
      >
        <Spinner />
        Confirming email address
      </div>
    </VerificationMessage>
  )
}

function VerificationMessage({
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
