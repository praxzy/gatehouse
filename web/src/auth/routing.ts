import type { CurrentUser } from '@/api/auth'

export function authenticatedDestination(user: CurrentUser, requestedReturnTo?: string | null) {
  const returnTo = safeReturnTo(requestedReturnTo)

  if (user.fully_authenticated) {
    return returnTo
  }

  const mfaPath = user.mfa_enrolled ? '/mfa/challenge' : '/mfa/enroll'

  if (returnTo === '/app') {
    return mfaPath
  }

  return `${mfaPath}?return_to=${encodeURIComponent(returnTo)}`
}

export function safeReturnTo(value?: string | null) {
  if (!value || !value.startsWith('/') || value.startsWith('//')) {
    return '/app'
  }

  return value
}

export function isAuthorizationContinuation(value: string) {
  return value === '/oauth/authorize/continue' || value.startsWith('/oauth/authorize/continue?')
}
