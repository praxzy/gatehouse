import { screen } from '@testing-library/react'
import { StrictMode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { VerifyEmailPage } from './VerifyEmailPage'
import { renderWithProviders } from '@/test/render'

describe('VerifyEmailPage', () => {
  it('verifies the token once under React Strict Mode', async () => {
    window.history.replaceState(
      window.history.state,
      '',
      '/verify-email#token=valid-verification-token',
    )

    const fetchMock = vi.fn().mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          window.setTimeout(() => {
            resolve(
              new Response(null, {
                status: 204,
              }),
            )
          }, 10)
        }),
    )

    vi.stubGlobal('fetch', fetchMock)

    renderWithProviders(
      <StrictMode>
        <VerifyEmailPage />
      </StrictMode>,
      {
        route: '/verify-email',
      },
    )

    expect(
      await screen.findByRole('heading', {
        name: 'Email verified',
      }),
    ).toBeInTheDocument()

    expect(window.location.hash).toBe('')
    expect(window.location.search).toBe('?verified=1')

    expect(fetchMock).toHaveBeenCalledOnce()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/email/verify',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify({
          token: 'valid-verification-token',
        }),
      }),
    )

    expect(
      screen.getByRole('link', {
        name: 'Continue to sign in',
      }),
    ).toHaveAttribute('href', '/login')
  })

  it('shows a generic error for an invalid or expired token', async () => {
    window.history.replaceState(
      window.history.state,
      '',
      '/verify-email#token=invalid-verification-token',
    )

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          error: 'invalid or expired verification link',
          request_id: 'req-email-verification',
        }),
        {
          status: 400,
          headers: {
            'Content-Type': 'application/json',
          },
        },
      ),
    )

    vi.stubGlobal('fetch', fetchMock)

    renderWithProviders(<VerifyEmailPage />, {
      route: '/verify-email',
    })

    expect(
      await screen.findByRole('heading', {
        name: 'We couldn’t verify your email',
      }),
    ).toBeInTheDocument()

    expect(screen.getByText('invalid or expired verification link')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledOnce()
  })
})
