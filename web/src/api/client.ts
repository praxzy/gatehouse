type APIErrorResponse = {
  error?: string
  request_id?: string
}

type APIRequestOptions = Omit<RequestInit, 'body'> & {
  body?: unknown
}

let csrfToken: string | null = null

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

export function setCSRFToken(token: string | null) {
  csrfToken = token
}

export async function apiRequest<T>(path: string, options: APIRequestOptions = {}): Promise<T> {
  const { body, headers: providedHeaders, ...requestOptions } = options

  const method = (requestOptions.method ?? 'GET').toUpperCase()
  const headers = new Headers(providedHeaders)

  headers.set('Accept', 'application/json')

  if (body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }

  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(`/api/v1${path}`, {
    ...requestOptions,
    method,
    headers,
    credentials: 'include',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  const responseCSRFToken = response.headers.get('X-CSRF-Token')
  if (responseCSRFToken) {
    csrfToken = responseCSRFToken
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

function isAPIErrorResponse(value: unknown): value is APIErrorResponse {
  return typeof value === 'object' && value !== null
}
