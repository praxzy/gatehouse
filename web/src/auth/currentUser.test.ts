import { describe, expect, it } from 'vitest'
import { APIError, APIUnavailableError } from '@/api/client'
import { shouldRetryCurrentUserRequest } from './currentUser'

describe('shouldRetryCurrentUserRequest', () => {
  it('retries network and server failures at most twice', () => {
    const networkError = new APIUnavailableError()
    const serverError = new APIError('service unavailable', 503)

    expect(shouldRetryCurrentUserRequest(0, networkError)).toBe(true)
    expect(shouldRetryCurrentUserRequest(1, serverError)).toBe(true)
    expect(shouldRetryCurrentUserRequest(2, networkError)).toBe(false)
  })

  it('does not retry authentication failures', () => {
    expect(shouldRetryCurrentUserRequest(0, new APIError('unauthorized', 401))).toBe(false)
  })
})
