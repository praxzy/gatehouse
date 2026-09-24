type APIErrorResponse = {
  error?: string
  request_id?: string
}

type CSRFTokenResponse = {
  csrf_token: string
}

type APIRequestOptions = Omit<RequestInit, 'body'> & {
  body?: unknown
}

let csrfToken: string | null = null
let csrfTokenPromise: Promise<string> | null = null

const csrfExemptMutationPaths = new Set([
  '/auth/register',
  '/auth/login',
  '/auth/email/verify',
  '/invitations/preview',
  '/invitations/accept',
])

const sessionChangingPaths = new Set([
  '/auth/login',
  '/auth/logout',
  '/auth/mfa/challenge/totp',
  '/auth/mfa/challenge/recovery',
])

export class APIError extends Error {
  readonly status: number
  readonly requestId?: string

  constructor(message: string, status: number, requestId?: string) {
    super(message)

    this.name = 'APIError'
    this.status = status
    this.requestId = requestId
  }
}

export class APIUnavailableError extends Error {
  constructor(cause?: unknown) {
    super('We couldn\u2019t connect to Gatehouse', { cause })

    this.name = 'APIUnavailableError'
  }
}

export function isServiceUnavailableError(error: unknown) {
  return error instanceof APIUnavailableError || (error instanceof APIError && error.status >= 500)
}

export function setCSRFToken(token: string | null) {
  csrfToken = token
  csrfTokenPromise = null
}

export async function apiRequest<T>(path: string, options: APIRequestOptions = {}): Promise<T> {
  const { body, headers: providedHeaders, ...requestOptions } = options

  const method = (requestOptions.method ?? 'GET').toUpperCase()
  const headers = new Headers(providedHeaders)

  headers.set('Accept', 'application/json')

  if (body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }

  if (requiresCSRFToken(path, method)) {
    headers.set('X-CSRF-Token', await getCSRFToken())
  }

  let response: Response

  try {
    response = await fetch(`/api/v1${path}`, {
      ...requestOptions,
      method,
      headers,
      credentials: 'include',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (error) {
    if (isAbortError(error)) {
      throw error
    }

    throw new APIUnavailableError(error)
  }

  const responseCSRFToken = response.headers.get('X-CSRF-Token')
  if (responseCSRFToken) {
    csrfToken = responseCSRFToken
  }

  if (response.status === 401) {
    setCSRFToken(null)
  }

  if (response.ok && sessionChangingPaths.has(path)) {
    setCSRFToken(null)
  }

  if (response.status === 204) {
    return undefined as T
  }

  const text = await response.text()
  let payload: unknown

  if (text !== '') {
    try {
      payload = JSON.parse(text)
    } catch {
      throw new APIError(
        'The server returned an invalid response',
        response.status,
        response.headers.get('X-Request-ID') ?? undefined,
      )
    }
  }

  if (!response.ok) {
    const error = isAPIErrorResponse(payload) ? payload : {}

    throw new APIError(
      error.error ?? 'Something went wrong',
      response.status,
      error.request_id ?? response.headers.get('X-Request-ID') ?? undefined,
    )
  }

  return payload as T
}

function requiresCSRFToken(path: string, method: string) {
  return !['GET', 'HEAD', 'OPTIONS'].includes(method) && !csrfExemptMutationPaths.has(path)
}

async function getCSRFToken() {
  if (csrfToken) {
    return csrfToken
  }

  if (!csrfTokenPromise) {
    csrfTokenPromise = apiRequest<CSRFTokenResponse>('/auth/csrf', {
      method: 'GET',
    })
      .then((response) => {
        if (!response.csrf_token) {
          throw new APIError('The server returned an invalid CSRF token', 500)
        }

        csrfToken = response.csrf_token
        return response.csrf_token
      })
      .finally(() => {
        csrfTokenPromise = null
      })
  }

  return csrfTokenPromise
}

function isAPIErrorResponse(value: unknown): value is APIErrorResponse {
  return typeof value === 'object' && value !== null
}

function isAbortError(error: unknown) {
  return error instanceof Error && error.name === 'AbortError'
}
