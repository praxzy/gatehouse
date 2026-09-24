import { beforeEach, describe, expect, it, vi } from 'vitest'

import { apiRequest, setCSRFToken } from '@/api/client'

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}

describe('apiRequest CSRF handling', () => {
  beforeEach(() => {
    setCSRFToken(null)
  })

  it('fetches and attaches a CSRF token to an authenticated mutation', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          csrf_token: 'session-csrf-token',
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          id: 'role-1',
        }),
      )

    vi.stubGlobal('fetch', fetchMock)

    await apiRequest('/roles', {
      method: 'POST',
      body: {
        name: 'Auditor',
      },
    })

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      '/api/v1/auth/csrf',
      expect.objectContaining({
        method: 'GET',
        credentials: 'include',
      }),
    )

    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      '/api/v1/roles',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    )

    const mutationOptions = fetchMock.mock.calls[1][1] as RequestInit
    const headers = new Headers(mutationOptions.headers)

    expect(headers.get('X-CSRF-Token')).toBe('session-csrf-token')
  })

  it('does not request a CSRF token for public login', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({
        next_step: 'authenticated',
      }),
    )

    vi.stubGlobal('fetch', fetchMock)

    await apiRequest('/auth/login', {
      method: 'POST',
      body: {
        email: 'alice@example.com',
        password: 'correct horse battery staple',
      },
    })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/login',
      expect.objectContaining({
        method: 'POST',
      }),
    )

    const options = fetchMock.mock.calls[0][1] as RequestInit
    const headers = new Headers(options.headers)

    expect(headers.has('X-CSRF-Token')).toBe(false)
  })

  it('reuses one token across authenticated mutations', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          csrf_token: 'cached-csrf-token',
        }),
      )
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(jsonResponse({}))

    vi.stubGlobal('fetch', fetchMock)

    await apiRequest('/roles', {
      method: 'POST',
      body: {
        name: 'Auditor',
      },
    })

    await apiRequest('/members', {
      method: 'POST',
      body: {
        email: 'bob@example.com',
      },
    })

    const csrfRequests = fetchMock.mock.calls.filter(([path]) => path === '/api/v1/auth/csrf')

    expect(csrfRequests).toHaveLength(1)
  })
})
